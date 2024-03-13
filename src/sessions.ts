// Dependencies ===============================================================

import crypto                         from 'node:crypto'
import bcrypt                         from 'bcrypt'
import EventEmitter                   from 'node:events'
import z, { object, string, boolean } from 'zod'
import type { AccountStore }          from './accounts.js'

// Types ======================================================================

interface SessionStoreSettings {
    sessionLength: {
        shortMinutes:    number
        longDays:        number
        elevatedMinutes: number
    }
}

interface SessionEntry {
    /** Account username */
    name: string
    /** Unique, non-changing UUID assigned to the account owner. */
    uuid: string
    /** Specifies whether the session belongs to a root user. */
    root: boolean
    /** 
     * Specifies whether the session has been elevated and has true root access.
     * For security, root sessions don't immediately have actual root privileges, 
     * the user must provide the password a second time to elevate it, after which 
     * it will quickly expire.
     */
    elevated: boolean
    /** Time of session's creation in ISO format. */
    createdISO: string
    /** Time of last session update or renewal in ISO format. */
    updatedISO: string
    /** 
     * Type of the session.  
     * hort sessions last a few hours, long sessions could
     * last months, and elevated sessions only last for a few minutes, as they have root access.
     */
    type: "short" | "long" | "elevated"
}

// Source =====================================================================

export class SessionStore extends EventEmitter<Record<LogLevel, any[]>> implements LogEventCapable {

    public scope = import.meta.url

    private declare settings: SessionStoreSettings
    private declare accounts: AccountStore

    // Session storage
    private cache = new Map<string, SessionEntry>()
    
    // Session cleanup and expiration
    private sci = 10_000 // Seconds
    private declare sct: NodeJS.Timer

    // Session ID byte-size
    private sidLength = 64

    private constructor() { super() }

    public static async open(accountStore: AccountStore, settings: SessionStoreSettings) {
        const self = new this()
        self.settings = settings
        self.accounts = accountStore
        self.sct = setInterval(() => {
            self._clearOldSessions()
        }, self.sci)
    }

    /**
     * Validates user credentials, creates a new session and returns its ID.
     * @param name Account name
     * @param pass Password
     * @param long Session type
     */
    public async create(name: string, pass: string, long: boolean): EavAsync<string, Error | 'WRONG_PASS_OR_NAME' | 'SID_GEN_ERROR'> {
        try {

            this.emit('notice', `SessionStore.create() call made | name:${name} long:${long}`)
            
            const account = await this.accounts.get(name)
            if (!account) return ['WRONG_PASS_OR_NAME', undefined]

            const doPasswordsMatch = await bcrypt.compare(pass, account.pass)
            if (!doPasswordsMatch) return ['WRONG_PASS_OR_NAME', undefined]

            const [SIDError, SID] = await this._getUniqueSID()
            this.emit('error', 'SessionStore.create() SID_GEN_ERROR:', SIDError)
            if (SIDError) return ['SID_GEN_ERROR', undefined]

            const created = new Date().toISOString()
            const session: SessionEntry = {
                name: account.name,
                uuid: account.uuid,
                root: account.root,
                elevated: false,
                createdISO: created,
                updatedISO: created,
                type: long ? 'long' : 'short'
            }

            this.cache.set(SID, session)
            this.emit('notice', `SessionStore.create() call successful | name:${name} long:${long} uuid:${session.uuid}`)
            return [undefined, SID]

        } 
        catch (error) {
            return [error as Error, undefined]
        }
    }

    /**
     * Validates the user session, corresponding account password and elevates the session.
     * The session is given an "elevated" type and will be subject to quick expiry, due to
     * the elevated root permissions.
     * @param sid Session ID
     * @param pass Account password
     */
    public async elevate(sid: string, pass: string) {
        try {

            this.emit('notice', `SessionStore.elevate() call made | SID:${sid.slice(0, 10)}...${sid.slice(-10)}`)
            
            const session = this.cache.get(sid)
            if (!session) return 'ERR_UNKNOWN_SESSION'
            if (!session.root) return 'ERR_ROOT_REQUIRED'

            const account = await this.accounts.get(session.name)
            if (!account) return 'ERR_UNKNOWN_ACCOUNT' // Unlikely scenario, but could "technically" happen.

            const doPasswordsMatch = await bcrypt.compare(pass, account.pass)
            if (!doPasswordsMatch) return "ERR_BAD_PASS"

            this.emit('notice', `SessionStore.elevate() call successful | SID:${sid.slice(0, 10)}...${sid.slice(-10)} user:${account.name}`)
            session.elevated = true

        } 
        catch (error) {
            return error as Error
        }
    }

    /**
     * Validates whether SID corresponds to an existing session and extends its duration.
     * The session object is returned if successful and `undefined` if not.
     * @param sid Session ID
     * @returns boolean
     */
    public renew(sid: string) {

        const session = this.cache.get(sid)
        if (!session) return undefined

        session.updatedISO = new Date().toISOString()
        return session

    }

    /**
     * Destroys the session corresponding to the given session ID and returns `boolean`
     * indicating whether the action was successful.
     * @param sid Session ID
     * @returns boolean
     */
    public destroy(sid: string) {
        return this.cache.delete(sid)
    }

    // Helper methods =========================================================

    private _getUniqueSID(): EavAsync<string> {
        return new Promise(resolve => {
            crypto.randomBytes(this.sidLength, async (error, bytes) => {

                // Catch cryptography errors, low system entropy, etc...
                if (error) {
                    this.emit('error', 'Session._getUniqueSID error:', error)
                    return resolve([error, undefined])
                }

                const SID = bytes.toString('base64')
                // Check if the session id is taken and generate a new one if true
                if (this.cache.get(SID)) return resolve(await this._getUniqueSID())
                else resolve([undefined, SID])

            })
        })
    }

    private async _clearOldSessions() {

        const now = Date.now()
        const sessionLengths: Record<SessionEntry["type"], number> = {
            short:    this.settings.sessionLength.shortMinutes    * 1000*60,
            long:     this.settings.sessionLength.longDays        * 1000*60*60*24,
            elevated: this.settings.sessionLength.elevatedMinutes * 1000*60
        }

        for (const [SID, session] of this.cache) {
            const sessionExpiryTime = new Date(session.updatedISO).getTime() + sessionLengths[session.type]
            const sessionExpired = now >= sessionExpiryTime

            if (sessionExpired) {
                this.cache.delete(SID)
                const sessionLastedMs = Date.now() - new Date(session.createdISO).getTime()
                const sessionLasted = {
                    long: (sessionLastedMs / (1000*60*60*24)).toFixed(1) + ' days',
                    short: (sessionLastedMs / (1000*60*60)).toFixed(1) + ' hours',
                    elevated: (sessionLastedMs / (1000*60*60)).toFixed(1) + ' hours'
                }[session.type]
                this.emit('info', `Session ${SID.slice(0, 10)}...${SID.slice(-10)} of "${session.uuid}" expired, lasted ${sessionLasted}, elevated: ${session.type === 'elevated'}`)
            }
        }

    }


}
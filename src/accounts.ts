// Dependencies ===============================================================

import crypto                                        from 'node:crypto'
import EventEmitter                                  from 'node:events'
import { DatabaseOptions, Level }                    from 'level'
import { AbstractSublevel, AbstractSublevelOptions } from 'abstract-level'
import z, { object, string, boolean }                from 'zod'
import bcrypt                                        from 'bcrypt'

// Types ======================================================================

interface AccountDBSettings {
    /** Location of the database. */
    storageLocation: string
    /** User account settings and safeguards. */
    user: {
        minUsernameLength: number 
        maxUsernameLength: number 
    }
    /** Password security */
    password: {
        minPasswordLength:      number
        useSpecialCharacters:   boolean
        useNumbers:             boolean
        useBigAndLittleSymbols: boolean
        saltRounds:             number
    }
}

interface UserAccount {
    name:         string
    pass:         string
    uuid:         string
    root:         boolean
    createdISO:   string
    lastLoginISO: null | string
}

// Used internally in the database. "name" is added when needed.
type UserAccountEntry = Omit<UserAccount, 'name'>

interface UserPreferences {
    [key: string]: string
}

// Source =====================================================================

export class AccountStore extends EventEmitter<Record<LogLevel, any[]>> implements LogEventCapable {

    public declare db:            Level<string, never>
    public declare slAccounts:    AbstractSublevel<typeof this.db, string | Buffer | Uint8Array, string, /* type */ UserAccountEntry>
    public declare slPreferences: AbstractSublevel<typeof this.db, string | Buffer | Uint8Array, string, /* type */ UserPreferences>

    public scope = import.meta.url

    constructor(private settings: AccountDBSettings) { super() }

    /** 
     * Opens the database.
     */
    public async open() {
        try {

            this.emit('info', 'Opening database.')

            const dbOptions: DatabaseOptions<string, never> = {
                keyEncoding: 'utf-8',
                valueEncoding: 'json'
            }
            const slOptions: AbstractSublevelOptions<string, any> = {
                keyEncoding: 'utf-8',
                valueEncoding: 'json'
            }
            
            this.db            = new Level(this.settings.storageLocation, dbOptions)
            this.slAccounts    = this.db.sublevel<string, UserAccountEntry>('account', slOptions)
            this.slPreferences = this.db.sublevel<string, UserPreferences>('pref', slOptions)
            
            // Wait till the DB is open and prevent server startup if it's misbehaving.
            await new Promise<void>((rs, rj) => this.db.defer(() => {
                if (this.db.status === 'closed') rj(new Error('User database got closed mid-initialization.'))
                else rs()
            }))

            this.emit('info', 'Database opened.')


            // Create the default administrator account
            const [usersError, users] = await this.listAccountEntries()
            if (usersError) return usersError
        
            if (users.filter(x => x.root).length === 0) {
                const err = await this.create({
                    name: 'admin',
                    pass: 'admin',
                    root: true
                }, true)
                if (err) return err as Error
                this.emit('critical', '!! IMPORTANT !! A default administrator account was created with username "admin" and password "admin". Update the password immediately!')
            }

        } 
        catch (error) {
            return error as Error
        }
    }

    /**
     * Closes the database.
     */
    public async close() {
        await this.db.close()
    }


    private CreateParams = object({
        name: string(),
        pass: string(),
        root: boolean()
    })
    /**
     * Creates a new user account with a given name password and root privileges.
     * @param user User information - username, password, root
     * @param skipChecks Whether to skip password strength checks (used for default admin account creation only)
     */
    public async create(user: z.infer<typeof this.CreateParams>, skipChecks = false) {
        try {
            
            this.emit('notice', `AccountStore.create() call made | user:${user.name}, root:${user.root}`)

            // Check if name is taken
            if (await this.exists(user.name)) return 'ERR_NAME_TAKEN'

            // Check against username and password security requirements
            if (!skipChecks) {
                if (!this.CreateParams.safeParse(user).success)                                return 'ERR_BAD_ENTRY'
                if (this.settings.user.minUsernameLength          > user.name.length)          return 'ERR_NAME_TOO_SHORT'
                if (this.settings.user.maxUsernameLength          < user.name.length)          return 'ERR_NAME_TOO_LONG'
                if (this.settings.password.minPasswordLength      > user.pass.length)          return 'ERR_PASS_TOO_SHORT'
                if (this.settings.password.useNumbers             && !/[0-9]/.test(user.pass)) return 'ERR_PASS_NO_NUMS'
                if (this.settings.password.useBigAndLittleSymbols && !/[A-Z]/.test(user.pass)) return 'ERR_PASS_NO_BIG_CHARS'
                if (this.settings.password.useBigAndLittleSymbols && !/[a-z]/.test(user.pass)) return 'ERR_PASS_NO_SMALL_CHARS'
                if (this.settings.password.useSpecialCharacters   && !/\W/   .test(user.pass)) return 'ERR_PASS_NO_SPECIAL_CHARS'
            }
            
            const pwdHash = await bcrypt.hash(user.pass, this.settings.password.saltRounds)
            const created = new Date().toISOString()
            const [idError, userID]  = await this._getUniqueUUID(user.name)
            if (idError) return idError

            await this.slAccounts.put(user.name, {
                pass: pwdHash,
                uuid: userID,
                root: user.root,
                createdISO: created,
                lastLoginISO: null
            })

            this.emit('notice', `AccountStore.create() call succeeded | user:${user.name}, root:${user.root}, uuid:${userID}`)

        } 
        catch (error) {
            this.emit('error', `Account.create() error:`, error)
            return error as Error
        }
    }

    /**
     * Deletes the user account specified by tne "name".  
     * Returns an error if any execution errors appear, if the user isn't found
     * or if is the last root in the database.
     * @param name Username of the account to delete.
     * @returns An error, if any happened.
     */
    public async delete(name: string) {
        try {

            this.emit('notice', `AccountStore.delete() call made | user:${name}`)

            // Check if user exists
            if (await this.exists(name) === false) return 'ERR_USER_NOT_FOUND'

            // Check if the username doesn't belong to the last admin account
            // and prevent cases where there wouldn't be any admin accounts at all.
            const [usersError, users] = await this.listAccountEntries()
            if (usersError) return usersError
            const admins = users.filter(x => x.root)
            if (admins.length === 1 && admins[0]!.name === name) return 'ERR_CANT_DEL_LAST_ADMIN'

            this.slAccounts.del(name)

            this.emit('notice', `AccountStore.delete() call successful | user:${name}`)
            
        } 
        catch (error) {
            this.emit('error', `Account.delete() error:`, error)
            return error as Error
        }
    }

    /**
     * Returns a list of all existing user accounts.
     * @returns Account entries array
     */
    public async listAccountEntries(): EavAsync<UserAccount[]> {
        try {
            const users: UserAccount[] = []
            for await (const name of this.slAccounts.keys()) {
                const user = await this.slAccounts.get(name) as UserAccount
                user.name = name
                users.push(user)
            }
            return [undefined, users]
        } 
        catch (error) {
            return [error as Error, undefined]
        }
    }

    /**
     * Returns a list of user account names.
     * @returns Account names
     */
    public async listUsers(): Promise<string[]> {
        return this.slAccounts.keys().all()
    }

    /**
     * Returns user account information, like the password hash, root privileges and a static UUID.
     * @param name Account username
     * @returns Account data
     */
    public async get(name: string): Promise<UserAccount | undefined> {
        try { 
            const user = await this.slAccounts.get(name) as UserAccount
            user.name = name
            return user
        } 
        catch { 
            return undefined 
        }
    }

    /**
     * Returns a `boolean` indicating whether the user of a given name exists.
     */
    public async exists(name: string){
        try {
            await this.slAccounts.get(name)
            return true  
        } 
        catch (error) {
            return false
        }
    }

    // Utility methods ========================================================

    private async _getUniqueUUID(username: string): EavAsync<string> {
        try {
            const id = `${username}.${crypto.randomUUID()}`
            const [usersError, users] = await this.listAccountEntries()
            if (usersError) return [usersError, undefined]
            if (users.find(x => x.uuid === id)) return await this._getUniqueUUID(username)
            return [undefined, id]
        } 
        catch (error) {
            return [error as Error, undefined]
        }
    }


}
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
    lastLoginISO: "never" | (string & {})
}

// Used internally in the database. "name" is added when needed.
type UserAccountEntry = Omit<UserAccount, 'name'>

interface UserPreferences {
    [key: string]: string
}

// Source =====================================================================

export class AccountStore extends EventEmitter<Record<LogLevel, any[]>> implements LogEventCapable {

    public  declare db:            Level<string, never>
    private declare slAccounts:    AbstractSublevel<typeof this.db, string | Buffer | Uint8Array, string, /* type */ UserAccountEntry>
    private declare slPreferences: AbstractSublevel<typeof this.db, string | Buffer | Uint8Array, string, /* type */ UserPreferences>
    private declare settings:      AccountDBSettings

    public scope = import.meta.url

    private constructor() { super() }

    /** 
     * Opens the database.
     */
    public static async open(settings: AccountDBSettings) {

        const self = new this()
        self.settings = settings

        const dbOptions: DatabaseOptions<string, never> = {
            keyEncoding: 'utf-8',
            valueEncoding: 'json'
        }
        const slOptions: AbstractSublevelOptions<string, any> = {
            keyEncoding: 'utf-8',
            valueEncoding: 'json'
        }


        self.emit('info', 'Opening database.')
        
        self.db            = new Level(settings.storageLocation, dbOptions)
        self.slAccounts    = self.db.sublevel<string, UserAccountEntry>('account', slOptions)
        self.slPreferences = self.db.sublevel<string, UserPreferences>('pref', slOptions)

        // Wait till the DB is open and prevent server startup if it's misbehaving.
        await new Promise<void>((rs, rj) => self.db.defer(() => {
            if (self.db.status === 'closed') rj(new Error('User database got closed mid-initialization.'))
            else rs()
        }))

        self.emit('info', 'Database opened.')

        if ((await self.listUsers()).length === 0) {
            await self.create({
                name: 'admin',
                pass: 'admin',
                root: true
            })
        }

        self.emit('critical', '!! IMPORTANT !! A default administrator account was created with username "admin" and password "admin". Update the password immediately!')

        return self

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
            
            this.emit('notice', `AccountStore.create() call made | name:${user.name}, root:${user.root}`)

            // Check if name is taken
            if (await this.exists(user.name)) return 'err_name_taken'

            // Check against username and password security requirements
            if (!skipChecks) {
                if (!this.CreateParams.safeParse(user).success)                                return 'err_bad_entry'
                if (this.settings.user.minUsernameLength          > user.name.length)          return 'err_name_too_short'
                if (this.settings.user.maxUsernameLength          < user.name.length)          return 'err_name_too_long'
                if (this.settings.password.minPasswordLength      > user.pass.length)          return 'err_pass_too_short'
                if (this.settings.password.useNumbers             && !/[0-9]/.test(user.pass)) return 'err_pass_no_nums'
                if (this.settings.password.useBigAndLittleSymbols && !/[A-Z]/.test(user.pass)) return 'err_pass_no_big_chars'
                if (this.settings.password.useBigAndLittleSymbols && !/[a-z]/.test(user.pass)) return 'err_pass_no_small_chars'
                if (this.settings.password.useSpecialCharacters   && !/\W/   .test(user.pass)) return 'err_pass_no_special_chars'
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
                lastLoginISO: 'never'
            })

            this.emit('notice', `AccountStore.create() call succeeded | name:${user.name}, root:${user.root}, uuid:${userID}`)

        } 
        catch (error) {
            this.emit('error', `Account.create() error:`, error)
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
    public async exists(name: string): Promise<boolean> {
        try {
            await this.slAccounts.get(name)
            return true    
        } 
        catch {
            return false
        }
    }

    // Utility methods ========================================================

    private async _getUniqueUUID(username: string): EavAsync<string> {
        try {
            const id = `${username}.${crypto.randomUUID()}`
            const [acErr, accounts] = await this.listAccountEntries()
            if (acErr) return [acErr, undefined]
            if (accounts.find(x => x.uuid === id)) return await this._getUniqueUUID(username)
            return [undefined, id]
        } 
        catch (error) {
            return [error as Error, undefined]
        }
    }


}
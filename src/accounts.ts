// Dependencies ===============================================================

import EventEmitter from "events"
import { DatabaseOptions, Level } from 'level'
import { AbstractSublevel, AbstractSublevelOptions } from 'abstract-level'
import z, { object, string, boolean } from 'zod'

// Types ======================================================================

interface AccountDBSettings {
    /** Location of the database. */
    storageLocation: string
}

interface UserAccount {
    username: string
    password: string
    uuid: string
    root: boolean
}

interface UserPreferences {

}

// Source =====================================================================

export class AccountStore extends EventEmitter<Record<LogLevel, any[]>> implements LogEventCapable {

    public  declare db:            Level<string, never>
    private declare slAccounts:    AbstractSublevel<typeof this.db, string | Buffer | Uint8Array, string, /* type */ UserAccount>
    private declare slPreferences: AbstractSublevel<typeof this.db, string | Buffer | Uint8Array, string, /* type */ UserPreferences>

    public scope = import.meta.url

    private constructor() { super() }

    public static async create(settings: AccountDBSettings) {

        const self = new this()

        const dbOptions: DatabaseOptions<string, never> = {
            keyEncoding: 'utf-8',
            valueEncoding: 'json'
        }
        const slOptions: AbstractSublevelOptions<string, any> = {
            keyEncoding: 'utf-8',
            valueEncoding: 'json'
        }

        self.emit('info', 'Opening database.')
        self.db = new Level(settings.storageLocation, dbOptions)
        self.slAccounts = self.db.sublevel<string, UserAccount>('account', slOptions)
        self.slPreferences = self.db.sublevel<string, UserPreferences>('pref', slOptions)

        // Wait till the DB is open and prevent server startup if it's misbehaving.
        await new Promise<void>((rs, rj) => self.db.defer(() => {
            if (self.db.status === 'closed') rj(new Error('User database got closed mid-initialization.'))
            else rs()
        }))

        return self

    }


}
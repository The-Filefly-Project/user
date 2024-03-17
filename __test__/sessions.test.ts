import { test, expect, describe, afterAll, beforeAll } from 'vitest'
import { AccountStore } from '../src/accounts.ts'
import { SessionStore } from '../src/sessions.ts'
import fs from 'node:fs/promises'
import path from 'node:path'
import url from 'node:url'

import 'type-utils'

const __filename = url.fileURLToPath(import.meta.url)
const __dirname = url.fileURLToPath(new URL('.', import.meta.url))

const wait = (time: number) => new Promise<void>(end => setTimeout(() => end(), time))

afterAll(async () => {
    fs.rm(path.join(__dirname, './temp/'), { recursive: true })
})
beforeAll(async () => {
    fs.mkdir(path.join(__dirname, './temp/'), { recursive: true })
})

describe('Session management', async () => {

    const ac = new AccountStore({
        storageLocation: path.join(__dirname, './temp'),
        user: {
            minUsernameLength: 4,
            maxUsernameLength: 100,
        },
        password: {
            minPasswordLength: 10,
            useSpecialCharacters: true,
            useNumbers: true,
            useBigAndLittleSymbols: true,
            saltRounds: 10,
        }
    })

    const s = new SessionStore(ac, {
        sessionLength: {
            shortMinutes:    60,
            longDays:        30,
            elevatedMinutes: 5,
        }
    })

    await ac.open()

    if (await ac.exists('admin') === false)
        await ac.create({ name: 'admin', pass: 'admin', root: true}, true)

    if (await ac.exists('user') === false)
        await ac.create({ name: 'user', pass: 'user', root: false}, true)

    describe('create()', async () => {

        test('create session', async () => {
            const [sidErr, sid] = await s.create('admin', 'admin', false)
            const session = s.get(sid!)!
            expect(sidErr).toBe(undefined)
            expect(sid).toBeTypeOf('string')
            expect(session.name).toBe('admin')
        })

        test('create session (bad name)', async () => {
            const [sidErr, sid] = await s.create('wrong-name', 'admin', false)
            const session = s.get(sid!)!
            expect(sidErr).toBe("WRONG_PASS_OR_NAME")
            expect(sid).toBe(undefined)
            expect(session).toBe(undefined)
        })

        test('create session (bad password)', async () => {
            const [sidErr, sid] = await s.create('admin', 'wrong-password', false)
            const session = s.get(sid!)!
            expect(sidErr).toBe("WRONG_PASS_OR_NAME")
            expect(sid).toBe(undefined)
            expect(session).toBe(undefined)
        })

        test('create session (long)', async () => {
            const [sidErr, sid] = await s.create('admin', 'admin', true)
            const session = s.get(sid!)!
            expect(sidErr).toBe(undefined)
            expect(session.type).toBe('long')
        })

    })

    describe('elevate()', async () => {

        test('elevate', async () => {
            const [sidErr, sid] = await s.create('admin', 'admin', false)
            const session = s.get(sid!)!
            const elevateErr = await s.elevate(sid!, 'admin')
            expect(elevateErr).toBe(undefined)
            expect(session.type).toBe('elevated')
        })

        test('elevate (bad password)', async () => {
            const [sidErr, sid] = await s.create('admin', 'admin', false)
            const session = s.get(sid!)!
            const elevateErr = await s.elevate(sid!, 'wrong-password')
            expect(elevateErr).toBe("ERR_BAD_PASS")
            expect(session.type).toBe('short')
        })

        test('elevate (bad SID)', async () => {
            const elevateErr = await s.elevate('wrong-session-id', 'admin')
            expect(elevateErr).toBe("ERR_UNKNOWN_SESSION")
        })

        test('elevate non-admin', async () => {
            const [sidErr, sid] = await s.create('user', 'user', false)
            const session = s.get(sid!)!
            const elevateErr = await s.elevate(sid!, 'user')
            expect(elevateErr).toBe('ERR_ROOT_REQUIRED')
            expect(session.type).toBe('short')
        })

    })

    describe('renew()', async () => {

        test('renew', async () => {
            const [_, sid] = await s.create('admin', 'admin', false)
            const created = new Date(s.get(sid!)!.updatedISO).getTime()
            await wait(100)
            const renewed = new Date(s.renew(sid!)!.updatedISO).getTime()
            expect(renewed).toBeGreaterThan(created)
        })

        test('renew (bad SID)', async () => {
            const sid = s.renew('some-wrong-sid')
            expect(sid).toBe(undefined)
        })

    })

})
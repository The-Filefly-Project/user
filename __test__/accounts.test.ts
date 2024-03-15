import { test, expect, describe, afterAll, beforeAll } from 'vitest'
import { AccountStore } from '../src/accounts.ts'
import fs from 'node:fs/promises'
import path from 'node:path'
import url from 'node:url'

import 'type-utils'

const __filename = url.fileURLToPath(import.meta.url)
const __dirname = url.fileURLToPath(new URL('.', import.meta.url))

afterAll(async () => {
    fs.rm(path.join(__dirname, './temp/'), { recursive: true })
})
beforeAll(async () => {
    fs.mkdir(path.join(__dirname, './temp/'), { recursive: true })
})

const name = () => Math.floor(Math.random() * 10000000).toString()
    + Math.floor(Math.random() * 10000000).toString()
    + Math.floor(Math.random() * 10000000).toString()
    + Math.floor(Math.random() * 10000000).toString()


describe('Account creation', async () => {

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
        
    await ac.open()
 
    describe('create + password strength checks', async () => {

        test('skip checks', async () => {
            const result = await ac.create({ name: name(), pass: 'user', root: false }, true)
            expect(result).toBe(undefined)
        })

        test("bad password, don't skip checks", async () => {
            const result = await ac.create({ name: name(), pass: 'user', root: false })
            expect(result).toBeDefined()
        })

        test("password length", async () => {
            const short = await ac.create({ name: name(), pass: '123',        root: true })
            const long =  await ac.create({ name: name(), pass: '1234567890', root: true })
            expect(short).toBe('ERR_PASS_TOO_SHORT')
            expect(long).not.toBe('ERR_PASS_TOO_SHORT')
        })

        test("password use numbers", async () => {
            const none = await ac.create({ name: name(), pass: 'creativePassword', root: false })
            const nums = await ac.create({ name: name(), pass: 'creativePassword1', root: false })
            expect(none).toBe('ERR_PASS_NO_NUMS')
            expect(nums).not.toBe('ERR_PASS_NO_NUMS')
        })

        test("password big chars", async () => {
            const small = await ac.create({ name: name(), pass: 'creativepassword1', root: false })
            const big   = await ac.create({ name: name(), pass: 'creativePassword1', root: false })
            expect(small).toBe('ERR_PASS_NO_BIG_CHARS')
            expect(big).not.toBe('ERR_PASS_NO_BIG_CHARS')
        })

        test("password small chars", async () => {
            const big   = await ac.create({ name: name(), pass: 'CREATIVEPASSWORD1', root: false })
            const small = await ac.create({ name: name(), pass: 'creativePassword1', root: false })
            expect(big).toBe('ERR_PASS_NO_SMALL_CHARS')
            expect(small).not.toBe('ERR_PASS_NO_SMALL_CHARS')
        })

        test("password special chars", async () => {
            const normal  = await ac.create({ name: name(), pass: 'CreativePassword1', root: false })
            const special = await ac.create({ name: name(), pass: 'CreativePassword1$', root: false })
            expect(normal).toBe('ERR_PASS_NO_SPECIAL_CHARS')
            expect(special).not.toBe('ERR_PASS_NO_SPECIAL_CHARS')
        })
        
    })

    describe('delete', async () => {

        test('try deleting last admin', async () => {
            const result = await ac.delete('admin')
            expect(result).toBe('ERR_CANT_DEL_LAST_ADMIN')
        })

        test('try deleting NOT a admin', async () => {
            await ac.create({ name: 'admin2', pass: 'admin2', root: true }, true)
            const result = await ac.delete('admin')
            expect(result).toBe(undefined)
        })

    })

    test('list account entries', async () => {
        const [err, result] = await ac.listAccountEntries()
        const names = result?.map(x => x.name)
        expect(err).toBe(undefined)
        expect(names?.includes('admin')).toBe(false)
        expect(names?.includes('admin2')).toBe(true)
    })

    test('list users (usernames)', async () => {
        const users = await ac.listUsers()
        expect(users.includes('admin')).toBe(false)
        expect(users.includes('admin2')).toBe(true)
    })

    describe('get', () => {

        test('get user', async () => {
            const user = await ac.get('admin2')
            expect(user?.name).toBe('admin2')
        })

        test('get user (expect error)', async () => {
            const user = await ac.get('admin123')
            expect(user?.name).toBe(undefined)
        })

    })


})
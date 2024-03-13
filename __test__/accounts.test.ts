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

    describe('password strength checks', () => {

        test('skip checks', async () => {
            const result = await ac.create({ name: name(), pass: 'user', root: true }, true)
            expect(result).toBe(undefined)
        })

        test("bad password, don't skip checks", async () => {
            const result = await ac.create({ name: name(), pass: 'user', root: true })
            expect(result).toBeDefined()
        })

        test("password length", async () => {
            const short = await ac.create({ name: name(), pass: '123',        root: true })
            const long =  await ac.create({ name: name(), pass: '1234567890', root: true })
            expect(short).toBe('ERR_PASS_TOO_SHORT')
            expect(long).not.toBe('ERR_PASS_TOO_SHORT')
        })

        test("password use numbers", async () => {
            const none = await ac.create({ name: name(), pass: 'creativePassword', root: true })
            const nums = await ac.create({ name: name(), pass: 'creativePassword1', root: true })
            expect(none).toBe('ERR_PASS_NO_NUMS')
            expect(nums).not.toBe('ERR_PASS_NO_NUMS')
        })

        test("password big chars", async () => {
            const small = await ac.create({ name: name(), pass: 'creativepassword1', root: true })
            const big   = await ac.create({ name: name(), pass: 'creativePassword1', root: true })
            expect(small).toBe('ERR_PASS_NO_BIG_CHARS')
            expect(big).not.toBe('ERR_PASS_NO_BIG_CHARS')
        })

        test("password small chars", async () => {
            const big   = await ac.create({ name: name(), pass: 'CREATIVEPASSWORD1', root: true })
            const small = await ac.create({ name: name(), pass: 'creativePassword1', root: true })
            expect(big).toBe('ERR_PASS_NO_SMALL_CHARS')
            expect(small).not.toBe('ERR_PASS_NO_SMALL_CHARS')
        })

        test("password special chars", async () => {
            const normal  = await ac.create({ name: name(), pass: 'CreativePassword1', root: true })
            const special = await ac.create({ name: name(), pass: 'CreativePassword1$', root: true })
            expect(normal).toBe('ERR_PASS_NO_SPECIAL_CHARS')
            expect(special).not.toBe('ERR_PASS_NO_SPECIAL_CHARS')
        })

    })

})
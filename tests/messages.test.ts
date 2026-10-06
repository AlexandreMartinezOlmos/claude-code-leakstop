import { expect, test } from 'claude-code/testing'
import { ADD_GITIGNORE, CANCEL, USE_ENV, answerNote, fileReadDeny, flatten, readDeny, readQuestion } from '../hooks/messages.ts'

test('Cancel tells the model not to retry and to ask the user', () => {
  const note = answerNote(CANCEL)
  expect(note.includes('The user chose Cancel')).toBe(true)
  expect(note.includes('do not retry')).toBe(true)
})

test('"Use environment variable" tells the model to do it now', () => {
  expect(answerNote(USE_ENV).includes('do that now')).toBe(true)
})

test('"Add to .gitignore" tells the model to add the files and retry', () => {
  expect(answerNote(ADD_GITIGNORE).includes('.gitignore now')).toBe(true)
})

test('no answer says nobody could be asked', () => {
  expect(answerNote(undefined).includes('could not ask the user')).toBe(true)
})

test('free text is relayed as the user words, never as an approval', () => {
  const note = answerNote('vale, adelante')
  expect(note.includes('answered: "vale, adelante"')).toBe(true)
  expect(note.includes('not an approval')).toBe(true)
})

test('free text is shortened and flattened', () => {
  const note = answerNote(`first\n\n${'x'.repeat(500)}`)
  expect(note.includes('\n')).toBe(false)
  expect(note.length < 400).toBe(true)
  expect(note.includes('…')).toBe(true)
})

test('denying a read of .env says how to add a variable without reading it', () => {
  expect(readDeny('.env', false).includes(">> .env")).toBe(true)
  expect(fileReadDeny(['.env']).includes(">> .env")).toBe(true)
})

test('flatten puts a question on one line, in order, without losing a word', () => {
  const one = flatten(readQuestion('.env'))
  expect(one.includes('\n')).toBe(false)
  expect(one).toBe("LeakStop · CRITICAL — Read of a sensitive file — .env — Its contents would enter the model's context and the session history. — How do you want to handle it?")
  expect(flatten('a\n\n  b  \n')).toBe('a — b')
})

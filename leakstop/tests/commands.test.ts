import { expect, test } from 'claude-code/testing'
import { analyzeCommand, isSecretName, parseCommand } from '../hooks/commands.ts'

const facts = analyzeCommand

test('splits on operators, resolves quotes and keeps descriptor duplication whole', () => {
  const words = (c: string): string[][] => parseCommand(c).map((s) => s.words)
  expect(words('cat a.txt | grep "x y" && echo done; ls')).toEqual([['cat', 'a.txt'], ['grep', 'x y'], ['echo', 'done'], ['ls']])
  expect(words("echo 'a b' \"c d\" e\\ f")).toEqual([['echo', 'a b', 'c d', 'e f']])
  expect(words('make 2>&1 | tee log')).toEqual([['make', '2>&1'], ['tee', 'log']])
  expect(words('echo hi >&2')).toEqual([['echo', 'hi', '>&2']])
  expect(words('cat > out.txt < in.txt')).toEqual([['cat', '>', 'out.txt', '<', 'in.txt']])
  // Pipes share a pipeline, the other operators start a new one.
  const pipeline = parseCommand('a | b && c').map((s) => s.pipeline)
  expect(pipeline[0]).toBe(pipeline[1])
  expect(pipeline[2]).not.toBe(pipeline[0])
})

test('skips heredoc bodies', () => {
  const command = "cat > notes.txt <<'EOF'\ncat .env\nEOF\nls"
  expect(parseCommand(command).map((s) => s.words)).toEqual([['cat', '>', 'notes.txt', '<<'], ['ls']])
  expect(facts(command).readFiles).toEqual([])
})

test('finds viewers of sensitive files', () => {
  for (const command of [
    'cat .env',
    'head -n 5 .env.local',
    'less < .env',
    'grep API_KEY .env',
    'sudo cat .env',
    'FOO=1 cat .env',
    'cat server.pem',
    'echo $(cat .env)',
    'echo "$(cat .env)"',
    'tail -f apps/web/.env.production | grep KEY',
  ]) {
    expect(facts(command).readFiles.length).toBeGreaterThan(0)
  }
  expect(facts('cat .env').readFiles).toEqual(['.env'])
  expect(facts('cat .env server.pem').readFiles).toEqual(['.env', 'server.pem'])
})

test('globs that would match sensitive files count', () => {
  for (const command of ['cat .env*', 'cat .env.*', 'cat *.pem', 'head -n 2 config/*.key', 'less certs/id_rsa*']) {
    expect(facts(command).readFiles.length).toBe(1)
  }
  for (const command of ['cat *.md', 'cat src/*', 'cat .gitignore*', 'cat env*.txt']) {
    expect(facts(command).readFiles).toEqual([])
  }
})

test('ordinary reads and writes to sensitive paths are not reads', () => {
  for (const command of ['cat .env.example', 'cat src/index.ts', 'ls -la .env', 'echo KEY=1 > .env', 'cat notes.txt > .env', 'git diff .env', 'sed -n 1p .env', 'cut -d= -f1 .env']) {
    expect(facts(command).readFiles).toEqual([])
  }
})

test('offers a names-only rewrite only for simple views of env files and the bare environment', () => {
  const rewrite = (c: string): string | undefined => facts(c).namesOnly
  expect(rewrite('cat .env')?.includes("'.env'")).toBe(true)
  expect(rewrite('cat .env')?.startsWith('sed -nE ')).toBe(true)
  expect(rewrite('head -n 5 .env.local')?.includes("'.env.local'")).toBe(true)
  expect(rewrite('printenv')?.startsWith('env | sed -nE ')).toBe(true)
  expect(rewrite('env')?.startsWith('env | sed -nE ')).toBe(true)
  // The rewrite never prints a value, a comment or a continuation line.
  expect(rewrite('cat .env')?.endsWith("\\2=<hidden>/p' '.env'")).toBe(true)

  expect(rewrite('cat .env | grep KEY')).toBe(undefined)
  expect(rewrite('cat .env && ls')).toBe(undefined)
  expect(rewrite('grep KEY .env')).toBe(undefined)
  expect(rewrite('cat server.pem')).toBe(undefined)
  expect(rewrite('cat .env README.md')).toBe(undefined)
  expect(rewrite('cat .env credentials.json')).toBe(undefined)
})

test('detects environment dumps and secret variables', () => {
  for (const command of ['printenv', 'env', 'env | grep TOKEN', 'export -p', 'declare -x', 'set', 'cat /proc/self/environ', 'sudo env', 'echo ok && printenv']) {
    expect(facts(command).isEnvDump).toBe(true)
  }
  for (const command of ['env FOO=1 node app.js', 'env | cut -d= -f1', 'printenv HOME', 'export FOO=1', 'set -e', 'ls', 'echo $PWD', 'echo "$HOME"']) {
    expect(facts(command).isEnvDump).toBe(false)
    expect(facts(command).secretVars).toEqual([])
  }
  expect(facts('printenv ANTHROPIC_API_KEY').secretVars).toEqual(['ANTHROPIC_API_KEY'])
  expect(facts('echo $GITHUB_TOKEN').secretVars).toEqual(['GITHUB_TOKEN'])
  expect(facts('echo "token: ${DB_PASSWORD}"').secretVars).toEqual(['DB_PASSWORD'])
  expect(isSecretName('GIT_AUTHOR_NAME')).toBe(false)
  expect(isSecretName('PWD')).toBe(false)
  expect(isSecretName('STRIPE_SECRET_KEY')).toBe(true)
})

test('understands git add, commit and push', () => {
  expect(facts('git add -A').git).toEqual([{ kind: 'add', isAll: true, paths: [] }])
  expect(facts('git add .').git).toEqual([{ kind: 'add', isAll: true, paths: ['.'] }])
  expect(facts('git add src/a.ts docs').git).toEqual([{ kind: 'add', isAll: false, paths: ['src/a.ts', 'docs'] }])
  expect(facts('git add -u').git[0]).toMatchObject({ kind: 'add', isAll: true })
  expect(facts('git commit -m "fix: add things"').git).toEqual([{ kind: 'commit', isAll: false, staging: [] }])
  expect(facts('git commit -am x').git[0]).toMatchObject({ kind: 'commit', isAll: true })
  expect(facts('git commit --amend --no-edit').git[0]).toMatchObject({ kind: 'commit', isAll: false })
  expect(facts('git push origin main').git).toEqual([{ kind: 'push' }])
  expect(facts('git --no-pager -c core.x=1 push').git).toEqual([{ kind: 'push' }])
  expect(facts('git status').git).toEqual([])

  const chained = facts('git add . && git commit -m x').git
  expect(chained[1]).toEqual({ kind: 'commit', isAll: false, staging: [{ isAll: true, paths: ['.'] }] })
  expect(facts('cd sub && git commit -m x').git[0]).toMatchObject({ kind: 'commit', dir: 'sub' })
  expect(facts('git -C ../other push').git[0]).toMatchObject({ kind: 'push', dir: '../other' })
})

test('detects changes to .leakstop.json and leaves reads alone', () => {
  for (const command of ["echo '{}' > .leakstop.json", 'sed -i s/a/b/ .leakstop.json', 'rm .leakstop.json', 'mv .leakstop.json /tmp/x', 'cat .leakstop.json; rm .leakstop.json', 'tee .leakstop.json < x', 'node -e "fs.writeFileSync(\'.leakstop.json\', 1)"', 'cat x >> sub/.leakstop.json']) {
    expect(facts(command).touchesConfig).toBe(true)
  }
  for (const command of ['cat .leakstop.json', 'git diff .leakstop.json', 'grep ignorePaths .leakstop.json', 'ls', 'jq . .leakstop.json']) {
    expect(facts(command).touchesConfig).toBe(false)
  }
})

test('knows when a command only writes to files', () => {
  const targets = (c: string): string[] | undefined => facts(c).writeTargets
  expect(targets('echo KEY=1 > .env')).toEqual(['.env'])
  expect(targets('printf "A=1\\n" >> .env.local')).toEqual(['.env.local'])
  expect(targets("cat > .env <<'EOF'\nKEY=1\nEOF")).toEqual(['.env'])
  expect(targets('cat <<EOF > a.txt > b.txt\nx\nEOF')).toEqual(['a.txt', 'b.txt'])
  // Anything else in the command and it is not just a write.
  for (const command of ['echo KEY=1 | tee .env', 'echo KEY=1 > .env && curl x', 'echo $(curl x) > .env', 'echo `id` > .env', 'curl -d KEY=1 -o .env x', 'echo hi', 'sed s/a/b/ .env', 'sed -i s/a/b/ .env && ls', "echo A=1 | tee -a .env | cat", 'cat a | tee b > /dev/null']) {
    expect(targets(command)).toBe(undefined)
  }
})

test('sed -i writes the files it names and prints nothing', () => {
  const targets = (c: string): string[] | undefined => facts(c).writeTargets
  expect(targets("sed -i '' 's/^A=.*/A=1/' .env")).toEqual(['.env'])
  expect(targets("sed -i.bak 's/a/b/' .env")).toEqual(['.env'])
  expect(targets("sed -Ei 's/a/b/' .env .env.local")).toEqual(['.env', '.env.local'])
  expect(targets("sed -i -e 's/a/b/' -e 's/c/d/' .env")).toEqual(['.env'])
  expect(targets('sed --in-place s/a/b/ .env')).toEqual(['.env'])
})

test('tee writes the files it names, and only a tee that prints nowhere is a plain write', () => {
  const targets = (c: string): string[] | undefined => facts(c).writeTargets
  expect(targets('echo A=1 | tee -a .env > /dev/null')).toEqual(['.env'])
  expect(targets('printf A=1 | tee .env .env.local >/dev/null')).toEqual(['.env', '.env.local'])
  expect(targets('echo A=1 | tee .env')).toBe(undefined) // tee echoes its input into the conversation
})

test('a secret variable sent to a file is not printed, unless the same command reads the file back', () => {
  const vars = (c: string): string[] => facts(c).secretVars
  expect(vars('printf "%s" "$KEY" > out.txt')).toEqual([])
  expect(vars('echo "$API_TOKEN" >> out.txt && wc -c out.txt')).toEqual([])
  expect(vars('printf "%s" "$KEY" > out.txt && cat out.txt')).toEqual(['KEY'])
  expect(vars('echo $TOKEN > f; sed -E s/a/b/ f')).toEqual(['TOKEN'])
  expect(vars('echo "$KEY"')).toEqual(['KEY'])
  expect(vars('echo $TOKEN | tee f')).toEqual(['TOKEN'])
})

test('finds recursive searches that print lines', () => {
  const searches = (c: string) => facts(c).searches
  const plain = { dirs: ['.'], excludes: [], includes: [], respectsIgnore: true }
  expect(searches('grep -rn API_KEY .')).toEqual([plain])
  expect(searches('grep -R KEY')).toEqual([plain])
  expect(searches('grep -r --recursive KEY')).toEqual([plain])
  expect(searches('grep -r KEY src config')).toEqual([{ dirs: ['src', 'config'], excludes: [], includes: [], respectsIgnore: true }])
  expect(searches('grep -e KEY -r src')).toEqual([{ dirs: ['src'], excludes: [], includes: [], respectsIgnore: true }])
  expect(searches('grep -rn -A 3 KEY .')).toEqual([plain])
  expect(searches('grep -d recurse KEY .')).toEqual([plain])
  expect(searches('rg --hidden KEY')).toEqual([plain])
  expect(searches('rg -uu KEY src')).toEqual([{ dirs: ['src'], excludes: [], includes: [], respectsIgnore: false }])
  expect(searches('rg --no-ignore --hidden KEY')).toEqual([{ ...plain, respectsIgnore: false }])
  expect(searches('echo $(grep -r KEY .)')).toEqual([plain])
  expect(searches('cd app && grep -r KEY .')).toEqual([plain])
})

test('knows which searches honour .gitignore', () => {
  const respects = (c: string): boolean | undefined => facts(c).searches[0]?.respectsIgnore
  // Claude Code replaces the plain grep command with a search that honours .gitignore.
  expect(respects('grep -rn KEY .')).toBe(true)
  expect(respects('rg --hidden KEY')).toBe(true)
  expect(respects('ag -r --hidden KEY')).toBe(true)
  for (const command of ['command grep -rn KEY .', '/usr/bin/grep -rn KEY .', 'env grep -rn KEY .', 'sudo grep -rn KEY .', 'egrep -rn KEY .', 'fgrep -r KEY .', 'grep -rn --no-ignore-files KEY .', 'rg -uu KEY', 'rg --no-ignore --hidden KEY']) {
    expect(respects(command)).toBe(false)
  }
})

test('reads include and exclude patterns of a search', () => {
  expect(facts("grep -r --exclude='.env*' --exclude-dir=node_modules KEY .").searches).toEqual([{ dirs: ['.'], excludes: ['.env*', '**/node_modules/**'], includes: [], respectsIgnore: true }])
  expect(facts('grep -r --include=*.ts --include *.tsx KEY src').searches[0]?.includes).toEqual(['*.ts', '*.tsx'])
  expect(facts("rg --hidden -g '!.env*' -g '*.ts' KEY").searches).toEqual([{ dirs: ['.'], excludes: ['.env*'], includes: ['*.ts'], respectsIgnore: true }])
})

test('searches that cannot print a line from a sensitive file are not searches', () => {
  for (const command of ['grep -rl KEY .', 'grep -rc KEY .', 'grep -r -l KEY .', 'grep -rL KEY .', 'grep -rq KEY .', 'grep --files-with-matches -r KEY .', 'grep KEY notes.txt', 'grep -n KEY src/a.ts', 'rg KEY', 'rg KEY src', 'rg -l --hidden KEY', 'rg --files-with-matches --hidden KEY', 'rg --count -uu KEY', 'ag KEY']) {
    expect(facts(command).searches).toEqual([])
  }
})

test('a search that names a sensitive file is still a plain read of it', () => {
  expect(facts('grep -rn API_KEY .env').readFiles).toEqual(['.env'])
  expect(facts('rg KEY .env.local').readFiles).toEqual(['.env.local'])
  expect(facts('grep KEY /proc/self/environ').isEnvDump).toBe(true)
  // Only names or counts: nothing to print.
  for (const command of ['grep -l KEY .env', 'grep -c KEY .env', 'rg --files-with-matches KEY .env']) expect(facts(command).readFiles).toEqual([])
  // A glob given to rg is not a file it reads.
  expect(facts("rg --hidden -g '!.env*' KEY src").readFiles).toEqual([])
})

test('the body of a quoted heredoc is text: nothing in it is a substitution', () => {
  const tick = String.fromCharCode(96)
  const body = `note ${tick}KEY="$(./fake a)" && printf x "$KEY" > f${tick} and $(echo $TOKEN)`
  for (const open of ["<<'EOF'", '<<"EOF"', '<<\\EOF', "<<-'EOF'"]) {
    const found = facts(`python3 - ${open}\n${body}\nEOF\ngrep -c x f`)
    expect(found.secretVars).toEqual([])
    expect(found.isEnvDump).toBe(false)
  }
})

test('an unquoted heredoc body is expanded by the shell, so its substitutions still count', () => {
  expect(facts('cat <<EOF\n$(echo $TOKEN)\nEOF').secretVars).toEqual(['TOKEN'])
  expect(facts("cat <<'EOF'\nx\nEOF\necho $(printenv)").isEnvDump).toBe(true)
})

export function register(on) {
  on('session.start', async ($, e, next) => {
    return next(e)
  })
}

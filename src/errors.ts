export class Failure extends Error {
  constructor(readonly code: string, message: string, readonly next: string, readonly exitCode = 1) {
    super(message)
  }
}

export class Failure extends Error {
  constructor(readonly code: string, message: string, readonly next: string, readonly exitCode = 1, readonly httpStatus?: number) {
    super(message)
  }
}

export function httpFailure(status: number, operation: 'Request' | 'Transfer'): Failure {
  return new Failure(status === 401 ? 'AUTH_REQUIRED' : status === 403 ? 'PERMISSION_DENIED' : status === 404 ? 'NOT_FOUND_OR_HIDDEN' : 'HTTP_ERROR',
    `${operation} returned HTTP ${status}.`, status === 400 ? 'Check the supplied API parameters against the selected operation schema.' :
      status === 501 && operation === 'Transfer' ? 'The server does not support this transfer formatter; check the selected operation and server release.' :
        'Check the configured identity and its permission for the selected operation.', 1, status)
}

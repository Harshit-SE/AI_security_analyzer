/**
 * Global error handler middleware  (middleware/errorHandler.js)
 *
 * Catches all errors forwarded via next(err) in route handlers.
 * In development: shows the error message for debugging.
 * In production:  returns a generic message — never leaks internals.
 *
 * SECURITY: Stack traces are NEVER sent to clients (they expose file paths,
 * internal library versions, and code structure). Stacks are only printed
 * to the server-side console in development mode.
 */

// eslint-disable-next-line no-unused-vars
export function errorHandler(err, req, res, next) {
  const isDev = process.env.NODE_ENV === 'development';

  // Always log the full stack server-side for debugging
  if (isDev) {
    console.error(`[Error Handler] ${req.method} ${req.path} — ${err.message}`);
    if (err.stack) console.error(err.stack);
  } else {
    // In production, log a brief message (no stack to avoid leaking paths in log aggregators)
    console.error(`[Error Handler] ${req.method} ${req.path} — ${err.message}`);
  }

  // Guard: if response was already started (e.g. streaming), don't try to send again
  if (res.headersSent) return;

  const status = typeof err.status === 'number' ? err.status : 500;

  // Never send stack traces to clients — in any environment.
  res.status(status).json({
    error: isDev ? err.message : 'An error occurred processing your request',
  });
}
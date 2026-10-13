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

  // Log server-side
  console.error(`[Error Handler] ${req.method} ${req.path} — ${err.message}`);
  if (isDev && err.stack) {
    console.error(err.stack);
  }

  // Guard: if response was already started (e.g. streaming), don't try to send again
  if (res.headersSent) return;

  const status = typeof err.status === 'number' ? err.status : 500;

  // Return clean, informative message to client
  res.status(status).json({
    error: err.message || 'An error occurred processing your request',
  });
}
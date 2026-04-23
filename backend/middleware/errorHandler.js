/**
 * Global error handler middleware  (middleware/errorHandler.js)
 *
 * Catches all errors forwarded via next(err) in route handlers.
 * In production: hides stack traces from clients.
 * In development: returns full error details for debugging.
 *
 * Bug fixes applied:
 *  1. Added check for res.headersSent to avoid "Cannot set headers after they are sent" crash
 *  2. Added 'next' parameter (required by Express for 4-param error handlers)
 *  3. Added structured JSON with 'error' and optional 'details' fields
 */

// eslint-disable-next-line no-unused-vars
export function errorHandler(err, req, res, next) {
  console.error(`[Error Handler] ${req.method} ${req.path} — ${err.message}`);
  if (err.stack && process.env.NODE_ENV !== 'production') {
    console.error(err.stack);
  }

  // Guard: if response was already started (e.g. streaming), don't try to send again
  if (res.headersSent) return;

  const status  = typeof err.status === 'number' ? err.status : 500;
  const isProd  = process.env.NODE_ENV === 'production';

  res.status(status).json({
    error:   isProd ? 'An error occurred processing your request' : err.message,
    ...(isProd ? {} : { details: err.stack }),
  });
}
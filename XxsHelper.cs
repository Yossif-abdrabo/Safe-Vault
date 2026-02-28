using System.Text.Encodings.Web;
using System.Text.RegularExpressions;

namespace SafeVault.Helpers
{
    /// <summary>
    /// Utility methods related to cross-site scripting (XSS) protection.
    ///
    /// In line with OWASP Top‑10 A1/A3 guidelines the class provides both
    /// *validation* (deny-by-default/allow-list) and *contextual encoding.
    /// Input validation should be performed early, and all output should be
    /// encoded according to the target context (HTML, attribute, JavaScript,
    /// URL, etc.).
    ///
    /// For production code you should consider a hardened library such as
    /// <c>Ganss.HtmlSanitizer</c> or Microsoft AntiXSS and apply a strict
    /// allow-list of permitted tags/attributes.  The examples here are
    /// intentionally simple to illustrate the principle.
    /// </summary>
    public static class XssHelper
    {
        private static readonly Regex _tagRegex =
            new(@"<.*?>", RegexOptions.Compiled | RegexOptions.Singleline);

        /// <summary>
        /// Applies a basic allow-list check to user input.
        /// Returns <c>true</c> if the value contains only alphanumeric characters
        /// and a handful of safe punctuation marks.  Reject any input where
        /// this method returns <c>false</c> rather than trying to scrub it later.
        /// </summary>
        public static bool IsSafeInput(string? text)
        {
            if (string.IsNullOrWhiteSpace(text))
                return true; // empty strings are fine

            // allow letters, digits, space, _, -, @, . and basic punctuation
            return Regex.IsMatch(text, "^[a-zA-Z0-9 \"_\\-@.]*$");
        }

        /// <summary>
        /// Returns <c>true</c> if the supplied text contains common patterns
        /// found in XSS payloads (scripts, javascript: URIs, event handlers).
        /// This is a heuristic and should not be relied upon alone; prefer
        /// encoding and allow-listing instead.
        /// </summary>
        public static bool IsXssAttempt(string? text)
        {
            if (string.IsNullOrWhiteSpace(text))
                return false;

            string lower = text.ToLowerInvariant();

            if (lower.Contains("<script") ||
                lower.Contains("javascript:") ||
                lower.Contains("onerror=") ||
                lower.Contains("onload=") ||
                lower.Contains("<img"))
            {
                return true;
            }

            // any remaining tags?
            return _tagRegex.IsMatch(text);
        }

        /// <summary>
        /// HTML-encodes the given text so it is safe to emit into an HTML
        /// element body.  This is the most common encoding and the default
        /// behaviour of Razor (`@model.Value`).
        /// </summary>
        public static string EncodeHtml(string? text)
        {
            if (text is null)
                return string.Empty;

            return HtmlEncoder.Default.Encode(text);
        }

        /// <summary>
        /// Encodes a value for use inside an attribute (e.g. &lt;input value="..."&gt;).
        /// </summary>
        public static string EncodeAttribute(string? text) => EncodeHtml(text);

        /// <summary>
        /// Encodes a string for safe inclusion in inline JavaScript contexts.
        /// </summary>
        public static string EncodeJs(string? text)
        {
            if (text is null)
                return string.Empty;

            return JavaScriptEncoder.Default.Encode(text);
        }

        /// <summary>
        /// Encodes a string for use in URLs (query parameters, etc.).
        /// </summary>
        public static string EncodeUrl(string? text)
        {
            if (text is null)
                return string.Empty;

            return UrlEncoder.Default.Encode(text);
        }

        /// <summary>
        /// Very simple sanitizer that strips HTML tags.  Useful when you want to
        /// preserve only plain text and have no need for a full HTML sanitizer.
        /// The implementation is intentionally naive; use a dedicated library
        /// when accepting rich HTML input.
        /// </summary>
        public static string StripTags(string? text) =>
            text is null ? string.Empty : _tagRegex.Replace(text, string.Empty);
    }
}
package io.github.murylloex.miniwaf;

/**
 * An uploaded file as the multipart layer describes it. Only the name is
 * inspected (by the dangerous-upload rules), never the content. Every member
 * is optional ({@code null}).
 */
public record UploadedFile(
    String fieldname,
    String name,
    String filename,
    String originalname
) {
    /** A file known only by its client-side name. */
    public static UploadedFile named(String name) {
        return new UploadedFile(null, name, null, null);
    }
}

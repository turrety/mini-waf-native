package io.github.murylloex.miniwaf;

import java.util.Map;

/**
 * Uploaded files as multipart layers hand them over: a flat list, or a map
 * of form field to files. {@code FilesBag.List} shadows {@code java.util.List}
 * inside this type.
 */
public sealed interface FilesBag {
    record List(java.util.List<UploadedFile> files) implements FilesBag {
        public List {
            files = java.util.List.copyOf(files);
        }
    }

    record Fields(
        Map<String, java.util.List<UploadedFile>> fields
    ) implements FilesBag {
        public Fields {
            fields = new java.util.LinkedHashMap<>(fields);
        }
    }

    static FilesBag from(java.util.List<UploadedFile> files) {
        return new List(files);
    }
}

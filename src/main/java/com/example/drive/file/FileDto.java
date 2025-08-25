package com.example.drive.file;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data @AllArgsConstructor
public class FileDto {
    private Long id;
    private String originalName;
    private long sizeBytes;
    private String contentType;
}


package com.example.drive.folder;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data @AllArgsConstructor
public class FolderDto {
    private Long id;
    private String name;
    private Long parentId;
}

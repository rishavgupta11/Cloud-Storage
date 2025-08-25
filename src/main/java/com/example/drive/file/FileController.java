package com.example.drive.file;

import com.example.drive.user.User;
import com.example.drive.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.Principal;
import java.util.List;

@RestController
@RequestMapping("/files")
@RequiredArgsConstructor
public class FileController {

    private final FileService fileService;
    private final UserRepository userRepo;

    private User getCurrentUser(Principal principal) {
        return userRepo.findByEmail(principal.getName())
                .orElseThrow(() -> new RuntimeException("User not found"));
    }

    @PostMapping("/upload")
    public FileDto upload(Principal principal,
                          @RequestParam("file") MultipartFile file,
                          @RequestParam(value = "parentId", required = false) Long parentId) throws Exception {
        User user = getCurrentUser(principal);
        FileObject fo = fileService.upload(file, parentId, user);
        return new FileDto(fo.getId(), fo.getOriginalName(), fo.getSizeBytes(), fo.getContentType());
    }

    @GetMapping("/by-folder/{parentId}")
    public List<FileDto> list(Principal principal, @PathVariable Long parentId) {
        User user = getCurrentUser(principal);
        return fileService.listByFolder(parentId, user).stream()
                .map(f -> new FileDto(f.getId(), f.getOriginalName(), f.getSizeBytes(), f.getContentType()))
                .toList();
    }

    @GetMapping("/{id}/download")
    public ResponseEntity<Resource> download(Principal principal, @PathVariable Long id) throws Exception {
        User user = getCurrentUser(principal);
        FileObject fo = fileService.requireOwnedFile(id, user);
        Path path = fileService.getPath(fo);
        Resource resource = new UrlResource(path.toUri());

        String encoded = URLEncoder.encode(fo.getOriginalName(), StandardCharsets.UTF_8)
                .replace("+", "%20");

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename*=UTF-8''" + encoded)
                .contentType(MediaType.parseMediaType(fo.getContentType() != null ? fo.getContentType() : "application/octet-stream"))
                .body(resource);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<String> delete(Principal principal, @PathVariable Long id) throws Exception {
        User user = getCurrentUser(principal);
        fileService.delete(id, user);
        return ResponseEntity.ok("File deleted");
    }

    @PutMapping("/{id}/rename")
    public FileDto rename(Principal principal,
                          @PathVariable Long id,
                          @RequestParam String newName) {
        User user = getCurrentUser(principal);
        FileObject fo = fileService.rename(id, newName, user);
        return new FileDto(fo.getId(), fo.getOriginalName(), fo.getSizeBytes(), fo.getContentType());
    }
}
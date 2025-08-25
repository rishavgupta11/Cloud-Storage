package com.example.drive.file;

import com.example.drive.config.JwtService;
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
import java.util.List;

@RestController
@RequestMapping("/files")
@RequiredArgsConstructor
public class FileController {

    private final FileService fileService;
    private final UserRepository userRepo;
    private final JwtService jwtService;

    private User currentUser(String authHeader) {
        String token = authHeader.replace("Bearer ", "");
        String email = jwtService.extractUsername(token);
        return userRepo.findByEmail(email).orElseThrow();
    }

    @PostMapping("/upload")
    public FileDto upload(@RequestHeader("Authorization") String auth,
                          @RequestParam("file") MultipartFile file,
                          @RequestParam(value = "parentId", required = false) Long parentId) throws Exception {
        User user = currentUser(auth);
        FileObject fo = fileService.upload(file, parentId, user);
        return new FileDto(fo.getId(), fo.getOriginalName(), fo.getSizeBytes(), fo.getContentType());
    }

    @GetMapping("/by-folder/{parentId}")
    public List<FileDto> list(@RequestHeader("Authorization") String auth,
                              @PathVariable Long parentId) {
        User user = currentUser(auth);
        return fileService.listByFolder(parentId, user).stream()
                .map(f -> new FileDto(f.getId(), f.getOriginalName(), f.getSizeBytes(), f.getContentType()))
                .toList();
    }

    @GetMapping("/{id}/download")
    public ResponseEntity<Resource> download(@RequestHeader("Authorization") String auth,
                                             @PathVariable Long id) throws Exception {
        User user = currentUser(auth);
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
    public ResponseEntity<String> delete(@RequestHeader("Authorization") String auth,
                                         @PathVariable Long id) throws Exception {
        User user = currentUser(auth);
        fileService.delete(id, user);
        return ResponseEntity.ok("File deleted");
    }

    @PutMapping("/{id}/rename")
    public FileDto rename(@RequestHeader("Authorization") String auth,
                          @PathVariable Long id,
                          @RequestParam String newName) {
        User user = currentUser(auth);
        FileObject fo = fileService.rename(id, newName, user);
        return new FileDto(fo.getId(), fo.getOriginalName(), fo.getSizeBytes(), fo.getContentType());
    }
}

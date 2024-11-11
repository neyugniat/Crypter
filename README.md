-   Build stub.cpp trước -> stub.exe đổi tên thành stub_cpp.exe cho khỏi trùng
-   Dùng tool để lấy mã hex của stub_cpp.exe, ở đây dùng HxD để export ra file stub.c

![Description of GIF](assets/export_char.gif)

-   copy toàn bộ mảng char trong stub.c vào crypter.cpp
-   build crypter.cpp -> crypter.exe
-   kéo thả file exe vào crypter.exe

![Description of GIF](assets/build_stub.gif)

-   Hoặc có thể dùng cmd:
    C:\path\to\crypter.exe C:\path\to\target.exe

![Description of GIF](assets/build_stub_2.gif)

-> ra file stub.exe là file malware

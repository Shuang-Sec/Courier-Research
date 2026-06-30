; 文件作用：MSVC x64 专用栈探测汇编桩，给大栈帧函数提供 _chkstk/__chkstk 入口。
;
; chkstk_x64.asm - Stack probe for MSVC x64 builds
; MSVC x64 does not support inline assembly, so this must be a separate file.
; Assemble with: ml64 /c chkstk_x64.asm
;

PUBLIC _chkstk
PUBLIC __chkstk

_TEXT SEGMENT

; _chkstk PROC 是主要栈探测入口。
_chkstk PROC
    push    rcx
    push    rax
    cmp     rax, 1000h
    lea     rcx, [rsp + 24]
    jb      done
probe_loop:
    sub     rcx, 1000h
    test    QWORD PTR [rcx], rcx
    sub     rax, 1000h
    cmp     rax, 1000h
    ja      probe_loop
done:
    sub     rcx, rax
    test    QWORD PTR [rcx], rcx
    pop     rax
    pop     rcx
    ret
_chkstk ENDP

; __chkstk PROC 是兼容别名，直接跳到 _chkstk。
__chkstk PROC
    ; Alias - some code paths call __chkstk instead of _chkstk
    jmp     _chkstk
__chkstk ENDP

_TEXT ENDS
END

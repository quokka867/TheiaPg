
PUBLIC HrdGetIF

PUBLIC HrdClacx64

PUBLIC HrdStacx64

PUBLIC HrdVoidx64

_TEXT SEGMENT

HrdGetIF PROC

pushfq

pop rax

shr eax,9

and al,1

movzx eax, al

ret

HrdGetIF ENDP

HrdClacx64 PROC

clac

ret

HrdClacx64 ENDP

HrdStacx64 PROC

stac

ret

HrdStacx64 ENDP

HrdVoidx64 PROC

ret

HrdVoidx64 ENDP

_TEXT ENDS

END

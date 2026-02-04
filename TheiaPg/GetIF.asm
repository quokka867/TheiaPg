PUBLIC HrdGetIF

_TEXT SEGMENT

HrdGetIF PROC

pushfq

pop rax

shr eax,9

and al,1

ret

HrdGetIF ENDP

_TEXT ENDS

END 

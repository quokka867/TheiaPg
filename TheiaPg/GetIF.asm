PUBLIC HrdGetIF

_TEXT SEGMENT

HrdGetIF PROC

pushfq

pop rcx

shr rcx,9

and cl,1

movzx eax,cl

ret

HrdGetIF ENDP

_TEXT ENDS

END 

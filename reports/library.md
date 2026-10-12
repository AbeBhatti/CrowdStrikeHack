# Defense library

Shared rules: 3

- exfil_role_window stage=exfil origin=fox validated=['fox', 'harrison', 'shaw', 'wardbeck', 'wheeler', 'wilson']
- webshell_on_webserver stage=webshell origin=harrison validated=['harrison', 'shaw', 'wardbeck', 'wheeler', 'wilson']
- reverse_shell_after_web stage=reverse_shell origin=fox validated=['fox', 'harrison', 'shaw', 'wardbeck', 'wheeler', 'wilson']

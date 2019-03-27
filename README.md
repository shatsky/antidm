DM is a Display Manager. antiDM is project aimed to make a display manager obsolete. Warning: very early stage.

Why do this? I think that widespread display managers add unneeded complexity and limit flexibility. They claim to support multiseat but in fact they take control of it from user, making it impossible to change per-seat configuration without restarting display manager, which means interrupting sessions on other seats.

Instead of monolithic display manager service I want to see something like getseat@seat.service instantiated service, much like getty@tty. There should be xinit-like program for starting display server and a client (perhaps for Xorg xinit itself can be used). This first client is, much like shadow-utils "login", a program which interactively asks for login and password, autheticates user and starts a chosen session before going into background and waiting until it has to end the session after the session process exits.

xlogin is such login program for Xorg. It's extremely simple and uses terminal emulator to interact with user.

Why not just use startx? Kernel VT subsystem is not multiseat aware, I need display server launched with seat argument to stay in so that input from input devices goes to the login program running on display attached to graphics card output of the same seat which input devices are attached to.

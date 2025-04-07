Hey claude!
welcome to the project, so I'm going to give you a run down of the project here:
The overall architecture is explained in @README.md
There is a remote device you can connect to, this remote device is called "khadas"
You can reach it by ssh using this command "ssh khadas@khadas"
we use this device as a remote encoder.
It has a camera attached to its ethernet port, the cameras IP address is: 192.168.2.90
Its username is "root" its password is "MINI_VScam00"
it is an Axis camera
The camera is known working.
The device "khadas" is reached over tailscale.
when you make changes to the "remote" you need to use rsync to move the changes over, you will use the path "khadas@khadas:~/remote"
you will not send over the target directory because khadas is a different architecture to this machine, it is an aarch64 machine, this machine is x86_64
If you have any quesitons, ask me, I always prefer you to seek clarity rather than make rash decisions.
When debugging, if something is not working, despite repeated attempts, let me know, and we will reassess it together.
Additionally to point out, I always prefer you to create mini proof of concepts to prove that something works rather than modifying the main codebase. These mini POCs
do not have to worry about the approval workflow etc, they just follow the QUIC/Gstreamer architecture. For instance lets say you are debugging gstreamer, create a like for like that just streams video from A to B using the same core architecture
just with none of the frills on it.
Also to note, whenever we are working on a feature, make this a crate, as much as possible use crates to separate functionality, this makes it easiser to debug
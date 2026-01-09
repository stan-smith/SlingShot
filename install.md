<h1 align="center">SlingShot Installation/Usage Guide</h1>

So, you want to install SlingShot, firstly you have a couple of options:
- Build from source
- Download precompiled binaries

Honestly I would recommend just sticking to the binaries in the releases page 
https://github.com/stan-smith/SlingShot/releases

You will find versions precompiled for AARCH64 and x86_64.

Should you wish to build from source, clone the repository, make sure you have cargo installed:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```
Once you have installed cargo, run:
```bash
cargo build --release
```
This is going to take some time, there's a fair amount to compile, go chuck the kettle on.

Once you have compiled the binaries, they will be in ../central ../central-setup ../remote ../remote-setup

<h2 align="center">Central Setup</h2>

I've tried to make this as <b>painless</b> as I can, but no promises made. 
So when you run the binary for the first time, you are going to be presented with some options:

<img width="518" height="210" alt="image" src="https://github.com/user-attachments/assets/70eddeef-d60a-4a45-8ecd-70891f5f2a12" />

We are going to be selecting the first option to proceed with the first time setup:

<img width="518" height="381" alt="image" src="https://github.com/user-attachments/assets/eb5345e8-f5ea-45bf-a8ff-d1657fd88746" />

To be honest with you, you can just mash enter through the ports bit, it will cause you less pain.
The interface selection determines which IP address is going to be broadcasting the RTSP streams, I would recommend consulting your local neighbourhood networks engineer if you are unsure about what this means.
Now that we've done that, onto the next stage:

<img width="772" height="1023" alt="image" src="https://github.com/user-attachments/assets/bf65a646-0074-440d-b021-4ac4d7d66bff" />

You will be asked to make your default admin account, and optionally provide a description.
The admin account has the ability to approve and deny nodes as well as full viewing rights/PTZ controls/stream parameters and recording downloading.
If you have issues scanning the QR code, Proton Authenticator I'm looking at you! Then just scan it in a QR scanning app.

<img width="772" height="581" alt="image" src="https://github.com/user-attachments/assets/18712748-541c-48f5-944f-441cc09fc6ca" />

Once you have confirmed the secret is correct, then we can move onto creating ONVIF credentials, this is still partially a work in progress, you'll see what I mean if you try to integrate it.
You will also be given the option to enable audit logging, this just tracks who does what with your cameras, as in which logged in user decided to issue PTZ commands.
That's the central configured! Go get another cuppa you, me and your mother are so proud <3  

<h2 align="center">Running the central</h2>

This is as simple as:
```bash
./target/release/central
```
Alternatively, the installer allows you to create a systemd service for the central node, which if that's your jam, then go for it.
I'm going to just treat it as if you're running as a service.
So you have pressed "install service" and then started it:

<img width="841" height="185" alt="image" src="https://github.com/user-attachments/assets/be3c6c93-9b53-489e-aa6b-37b71b837b5b" />

We can now access the webUI using the url:
http://youripyouconfigured:8081
Go ahead and login with your admin account and TOTP

Once inside it should be pretty self explanatory how to get around, but we will leave the central there for now

<h2 align="center">Remote Setup</h2>

So you have an SBC, tiny office PC, or massive server, and you want to take in RTSP feeds, transcode them and shoot them over QUIC.
Go ahead and grab the latest version of the release binary for your device, please change the giant CHANGEME text to be the latest release, and your architecture:
```bash
wget https://github.com/stan-smith/SlingShot/releases/download/(CHANGEME)/remote-linux-(CHANGEME)
wget https://github.com/stan-smith/SlingShot/releases/download/(CHANGEME)/remote-setup-linux-(CHANGEME)
```
Once on your device, you will need to be a privileged user for the installation if you want a systemd service for it.
Add the executable bits to the binaries:
```bash
sudo chmod +x remote-linux-arm64
sudo chmod +x remote-setup-linux-arm64
```
Now we can run the remote setup:
```bash
./remote-setup-linux-arm64
```
Where we will be taken to another delightful interactive installer:

<img width="459" height="201" alt="image" src="https://github.com/user-attachments/assets/69712f9e-7701-41ad-8b84-d4cfe01a00fa" />

In here we're just going to hit enter on "Configure node settings"
Then it's going to ask you a series of questions:
Here I am connecting to an Axis camera I have plugged into it

<img width="459" height="320" alt="image" src="https://github.com/user-attachments/assets/9a5f17b2-e2c4-4159-8d83-889480e00870" />

You will be asked which profile you want to transcode should you choose an ONVIF camera with multiple profiles
You will also be asked if you want to enable adaptive bitrate streaming, this is somewhat a work in progress, but it does work quite well!

Should you want to record locally, there is a wizard inside this wizard which lets you configure your storage medium:
  
<img width="690" height="370" alt="image" src="https://github.com/user-attachments/assets/1f8d3a1a-ec60-4260-a5d9-a103171543c1" />

Once all mounted, go ahead and install it as a systemd service

<img width="476" height="335" alt="image" src="https://github.com/user-attachments/assets/71ee536f-19b5-42f1-a83e-fe26f4447f0d" />

Once you hit start now, have a look at the webUI for your admin interface.
With any luck, you should see the device appear, and once you have allowed it access you will get a view like this:

<img width="1920" height="1040" alt="Screenshot_20260108_171848" src="https://github.com/user-attachments/assets/5dbfd1cc-6b25-4e8d-babd-af626c5e6a7e" />

<b>Congratulations! You have configured the system!</b>

Now get to installing 100 more!
In all seriousness, at this point, explore the features of the webUI, give the dynamic stream tuning a try, and once your recordings start writing to disc, then try retrieving them.
As of V1.0.0 they will write to disc on the central node at:
```
/home/(user-who-it-runs-as)/Videos/SlingShot/(remote-name-you-downloaded-from)
```

The HLS viewer is not very latency conscious I appreciate, so for your convenience, and to be honest the whole purpose of this project, there is an RTSP server which will serve your incoming H264 video straight out at:
```
rtsp://(configured-interface):8554/(remote-name-you-are-trying-to-watch)/stream
```

For instance if you had a node called "test1" and your central was set up to use 192.168.1.100, you could view that with:
```bash
ffplay rtsp://192.168.1.100:8554/test1/stream
```

There are lots of themes available for the webUI, I couldn't decide which ones to get rid of so I've just kept them all, "Industrial Ops" is easily my fave.

<b>I Hope this guide has been useful</b>

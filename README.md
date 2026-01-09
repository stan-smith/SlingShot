<h1 align="center">SlingShot</h1>

<p align="center"><b>Send video from anywhere to anywhere across any network</b></p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-AGPL%203.0-blue.svg" alt="License: AGPL-3.0"></a>
</p>

---

<h2 align="center">The Problem</h2>

There is currently a problem in the security industry.

If you want to send video from one place to another, you're going to be spending potentially $100K plus for a few feeds.

Enter stage left, SlingShot.



<h2 align="center">What is SlingShot?</h2>

SlingShot is built from the ground up to be modern; that means using <b>QUIC</b> for video transmission instead of TCP, it means writing in <b>Rust</b> instead of C, and it means using <b>open, proven cryptographic standards instead of something insecure.</b>


<h2 align="center">So what can I actually do with this?</h2>


Currently you can connect to an RTSP stream, either directly, or via an ONVIF compatible security camera, and then stream this video back to your central node via QUIC.

You can also record locally to the device, and optionally encrypt the recordings.

In this streaming process, you can set transcoding parameters, i.e. Resolution, FPS, Bitrate. You can also allow the system to decide this for you with my rudimentary Adaptive Bitrate implementation.

Once video reaches the central node, it is then retransmitted through an RTSP server, so you get RTSP out the other end of it. You can also view the video through an HLS based player in the webUI.

It is designed to be as easy to use as possible, and as lightweight as possible.

There is no fancy on device UI for configuration, this is all done in an interactive wizard.

This is great for mobile CCTV, remote operations, covert surveillance, allowing you to attach a great camera to a networked device and see the results from a safe distance.


<h2 align="center">Yeah, yeah, yeah, how do I install it?</h2>



I'm working on a one liner for the central and remote units at the moment, but in the meantime, go to [install.md](install.md) — it'll explain it in great detail.



<h2 align="center">Web UI</h2>

Management of remote nodes is done via a webUI, within this webUI you are able to:

- Request downloads from the remote unit to the central node.
- Pan Tilt Zoom operations on ONVIF cameras.
- Change transcoding parameters, resolution, FPS, bitrate.
- Node management/administration, allow/deny devices joining your central node.
- User administration, addition of administrators or users.

<h2 align="center">So, what I'm guessing I need like a Jetson Nano to run this?</h2>

No! You can run this on a Pi4!

You only need a few hundred MB of RAM, and a decent-ish CPU from the last 10 years and you should be able to transcode a 1080p 25fps source reliably without much stutter.

This uses x264enc from GStreamer to perform encoding operations, which is what 99.99% of the industry uses anyway. It's robust, low power, and royalty free.

I'm working on adding hardware support, and this won't take long to implement. I'm especially looking at Rockchip and NVENC as I know from personal experience what the demand will be.



<h2 align="center">How scalable is this?</h2>

So on my test rig, I spun up 50 test instances of the remote, they run a docker container which streams the FFMPEG test card at 1080p/30fps. The central node didn't even break a sweat.




<h2 align="center">Version 1.0.0</h2>

This is release 1.0.0, so as such expect there to be some bugs. I've been pretty meticulous, but I expect that the power of the internet will show me my mistakes ;)

I want this to be as open as possible, forever, hence why I'm releasing this under AGPL-3.0.

I would love it if we could get a community going, improving the capabilities of this!



<h2 align="center">Tested Cameras</h2>

There will be a list of currently known working cameras coming soon but for now I have tested:

| Camera | Firmware | Status |
|--------|----------|--------|
| AXIS M5525-E | 8.40.59 | ✅ Fully working |
| Samsung Techwin XNP-6400R | 2.01.04_20220112_R301 | ✅ Fully working |



<h2 align="center">What's next in the development cycle then?</h2>

In order of priority:

1. Language support — Spanish, Portuguese, French, German
2. Hardware transcoding support
3. Audio support
4. Changing from HLS to WebRTC probably
5. Finishing the ONVIF integration — this is a tricky one because literally every VMS does this differently and it's not exactly easy getting trial licenses for them all/actually working with them all.



<h2 align="center">Notes</h2>

As you are looking through this software's commit history, you'll probably see quite a few references to "kaiju" — this is just what I call all my projects before I finish them.

<h2 align="center">Licence</h2>

[AGPL-3.0](LICENSE)

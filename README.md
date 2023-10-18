# Introduction
This repository contains all data of the Bachelor Thesis in Computer Science of Markus Salvisberg and Remo Meyer at the Bern University of Applied Science 2022/2023.

# Thesis topic
In the booming age of IoT and Industry 4.x, the questions of what data to share and with whom become obvious. Not so obvious is the answer to the question 'how' data can be shared. The following is about sharing data, via MQTT brokers. Nowadays, it is common to create access via VPN (Virtual Private Network), so that private MQTT brokers can be accessed from outside. However, this type of 'private sharing' requires in-depth network configurations, hence is managed at the companies or individual network level. In this bachelor thesis, we want to elaborate the question, whether more lightweight solutions are possible that can be applied and managed directly at the application level. Specifically, the possibilities of bridging, a core functionality of the MQTT protocol, will be explored. Furthermore, the possibility of 'tunneling' data with the help of WebRTC will be explored. Both variants aim to share data privately and authentically without having to make profound network settings. It must therefore be possible to manage the whole thing on the application layer with none or minimal external dependencies.

# Structure
## doc

### book
A [page](/doc/book/bridge-the-gap_book.pdf) for the "book" with all thesis of this semester.

### thesis
The thesis [documentation](/doc/thesis/thesis_salvm4-meyer5.pdf).

### poster
A [poster](/doc/poster/bridging-the-gap_MarkusSalvisberg&RemoMeyer.pptx) for the final day exhibition.

### presentation
The [final day](/doc/presentation/thesis_presentation.pptx) and the [defense](/doc/presentation/thesis_verteidigung.pptx) presentations. 

### video
A short [video](/doc/video/bridging_the_gap_MarkusSalvisberg&RemoMeyer.mp4) of the thesis.

### rtt_measurement
[Raw data](/doc/rtt_measurement) of the round trip time analysis.

## prototypes
All [code](/prototypes/aiortc-python) written during the thesis. It contains an application to tunnel an application layer by WebRTC, a secure bridge application and several configuration files. All applications can be build as a flatpak. 

# Licence
All code is released under the [BSD 3-Clause License](/LICENSE).

# Note
This repository represents the end result of the bachelor thesis and won't be maintained in the future. During the thesis a private repository has been used on a gitlab server hosted by the Bern University of Applied Science.



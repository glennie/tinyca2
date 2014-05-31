#!/bin/bash

mkdir -p locale/de/LC_MESSAGES
mkdir -p locale/es/LC_MESSAGES
mkdir -p locale/cs/LC_MESSAGES

msgfmt po/de.po -o locale/de/LC_MESSAGES/tinyca2.mo
msgfmt po/es.po -o locale/es/LC_MESSAGES/tinyca2.mo
msgfmt po/cs.po -o locale/cs/LC_MESSAGES/tinyca2.mo

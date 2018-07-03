#!/usr/bin/env bash

output=$(PYTHONIOENCODING=utf-8 ./glep63-check -a)
devs=( $( echo "${output}" | sed -n -e 's/^.*<\(.*@gentoo.org\)>.*$/\1/p' | sort -u ) )
nl=$'\n'

counter=0
for dev in "${devs[@]}"; do
	if [[ $(( counter++ )) -eq 10 ]]; then
		echo "[press enter to continue]"
		read
		counter=0
	fi

	devout=$(echo "${output}" | grep "${dev}")
	keyids=( $(echo "${devout}" | cut -d' ' -f1 | cut -d: -f1 | sort -u) )
	gpgout=$(LC_MESSAGES=C gpg --list-keys "${keyids[@]}")

	echo "${dev}"
	xdg-open "https://bugs.gentoo.org/enter_bug.cgi?product=Gentoo+Infrastructure&component=Developer+account+issues&assigned_to=${dev}&blocked=659842&short_desc=${dev%@*}:+OpenPGP+key+does+not+conform+to+GLEP+63&comment=Your+key+does+not+seem+to+conform+to+GLEP+63+[1].+glep63-check+[2]+indicates:%0a%0a${devout//${nl}/%0a}%0a%0a${gpgout//${nl}/%0a}%0a%0aPlease+see+the+tracker+bug+for+tips+on+fixing+your+key.%0a%0a[1]:https://www.gentoo.org/glep/glep-0063.html%0a[2]:https://github.com/mgorny/glep63-check"
done

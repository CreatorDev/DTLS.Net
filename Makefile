DTLS_VERSION:=1.0.19

.PHONY: all
all: src/DTLS.Net/bin/Release/DTLS.Net.$(DTLS_VERSION).nupkg

src/DTLS.Net/bin/Release/DTLS.Net.$(DTLS_VERSION).nupkg:
	docker run -v $(PWD):/app --entrypoint /app/pack.sh creatordev/dotnet-mono-base Release src/DTLS.Net

.PHONY: clean
clean:
	rm -rf src/DTLS.Net/bin src/DTLS.Net/obj src/DTLS.Net/project.lock.json

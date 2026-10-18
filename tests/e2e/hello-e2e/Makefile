CFLAGS ?= -O2 -g

hello-e2e: hello.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $<

install: hello-e2e
	install -D -m 0755 hello-e2e $(DESTDIR)/usr/bin/hello-e2e
	install -D -m 0644 greeting $(DESTDIR)/usr/share/hello-e2e/greeting
	gzip -9 -c greeting >$(DESTDIR)/usr/share/hello-e2e/greeting.gz
	perl mkfiles.pl $(DESTDIR)/usr/share/hello-e2e
	install -D -m 0644 hello-e2e.conf $(DESTDIR)/etc/hello-e2e.conf
	ln -s hello-e2e $(DESTDIR)/usr/bin/hello-e2e-link

clean:
	rm -f hello-e2e

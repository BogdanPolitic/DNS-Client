ifeq (run,$(firstword $(MAKECMDGOALS)))
  RUN_ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
  $(eval $(RUN_ARGS):;@:)

endif

build:
	gcc dnsclient.c -o dnsclient

run:
	./dnsclient $(RUN_ARGS)

clean:
	rm -f *.o dnsclient message.log dns.log

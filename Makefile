PYTHON ?= python3
OPENSSH_REGRESS := tests/openssh-regress/run.py

.PHONY: openssh-regress openssh-regress-list openssh-regress-selftest openssh-regress-update

openssh-regress:
	$(PYTHON) $(OPENSSH_REGRESS)

openssh-regress-list:
	$(PYTHON) $(OPENSSH_REGRESS) --list

openssh-regress-selftest:
	$(PYTHON) -m unittest discover -s tests/openssh-regress -p 'test_*.py' -v

openssh-regress-update:
	$(PYTHON) $(OPENSSH_REGRESS) --results tests/openssh-regress/results.json --update-baseline

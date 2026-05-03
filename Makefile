.PHONY: help build test test-dynamic check shell clean

IMAGE := tabledevil/matt

help:
	@echo "MATT Container Build System"
	@echo ""
	@echo "  build         Build the MATT container image"
	@echo "  test          Run host-safe tests inside the container"
	@echo "  test-dynamic  Run docker-only tests (box-js, libzbar, dynamic analysis)"
	@echo "  check         Run matt --check (verify analyzer deps)"
	@echo "  shell         Interactive shell with ./data:/data mount"
	@echo "  clean         Remove the built image"

build:
	docker build -t $(IMAGE) .

test:
	docker run --rm $(IMAGE) matt --check
	docker run --rm $(IMAGE) python -m pytest tests/ -x -q

# Dynamic-analysis tests (marked @pytest.mark.docker) detonate
# attacker-controlled bytes through box-js etc. Only safe inside the
# container — refuse to run on the host.
test-dynamic:
	docker run --rm -e MATT_IN_DOCKER=1 $(IMAGE) \
	    python -m pytest tests/ -m docker -v

check:
	docker run --rm $(IMAGE) matt --check

shell:
	docker run -it --rm -v "$$(pwd)/data:/data" $(IMAGE)

clean:
	-docker rmi $(IMAGE)

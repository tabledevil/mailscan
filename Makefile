.PHONY: help build test check shell clean

IMAGE := tabledevil/matt

help:
	@echo "MATT Container Build System"
	@echo ""
	@echo "  build   Build the MATT container image"
	@echo "  test    Run tests inside the container"
	@echo "  check   Run matt --check (verify analyzer deps)"
	@echo "  shell   Interactive shell with ./data:/data mount"
	@echo "  clean   Remove the built image"

build:
	docker build -t $(IMAGE) .

test:
	docker run --rm $(IMAGE) matt --check
	docker run --rm $(IMAGE) python -m pytest tests/ -x -q

check:
	docker run --rm $(IMAGE) matt --check

shell:
	docker run -it --rm -v "$$(pwd)/data:/data" $(IMAGE)

clean:
	-docker rmi $(IMAGE)

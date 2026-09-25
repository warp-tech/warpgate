image-ssh-server:
	cd images/ssh-server && docker build -t warpgate-e2e-ssh-server .

image-mysql-server:
	cd images/mysql-server && docker build -t warpgate-e2e-mysql-server .

image-mariadb-server:
	cd images/mariadb-server && docker build -t warpgate-e2e-mariadb-server .

image-postgres-server:
	cd images/postgres-server && docker build -t warpgate-e2e-postgres-server .

image-vnc-server:
	cd images/vnc-server && docker build -t warpgate-e2e-vnc-server .

image-rdp-server:
	cd images/rdp-server && docker build -t warpgate-e2e-rdp-server .

pull-images:
	docker pull cgr.dev/chainguard/minio@sha256:bd014394a80898e68c149f2311fdf8d5a2c2f3bb2c33b9327ae6d02b4b065ae1 || true

all: image-ssh-server image-mysql-server image-mariadb-server image-postgres-server image-vnc-server image-rdp-server pull-images

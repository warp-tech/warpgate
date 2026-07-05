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

all: image-ssh-server image-mysql-server image-mariadb-server image-postgres-server image-vnc-server image-rdp-server

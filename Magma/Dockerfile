FROM cruizba/ubuntu-dind

ENV DEBIAN_FRONTEND=noninteractive

RUN apt -y update && apt -y upgrade
RUN apt -y install python3 python3-dev curl git python3-pip rsync jq parallel python-is-python3 sudo

RUN pip3 install --break-system-packages pandas

ARG USER=ubuntu
RUN echo "${USER} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/${USER} 
RUN groupadd docker || true && usermod -aG docker ${USER}

ADD . /magma
WORKDIR /magma

# CMD ["/bin/sh", "-c", "sleep 30s && /usr/bin/chown root:docker /var/run/docker.sock && sudo -u ubuntu /magma/run_experiment.sh $TARGET $HARNESS"]
CMD ["/bin/sh", "-c", "sleep 30s && /usr/bin/chown root:docker /var/run/docker.sock && sudo -u ubuntu /magma/run_afl_fuzzing.sh $TARGET $HARNESS"]

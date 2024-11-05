typedef struct pfds_t{
    struct pollfd *pfd;
    int fd_count;
    int fd_size;
}pfds_t;

void pfds_init(pfds_t *pfds, int size)
{
    pfds->pfd = (struct pollfd *)malloc(size*sizeof(*(pfds->pfd)));
    assert(pfds->pfd);

    pfds->fd_count = 0;
    pfds->fd_size  = size;
}

void pfds_add(pfds_t *pfds, int newfd)
{
    if(pfds->fd_count == pfds->fd_size){
        pfds->fd_size*=2;
        pfds->pfd = (struct pollfd *)realloc(pfds->pfd, pfds->fd_size*sizeof(*(pfds->pfd)));
        assert(pfds->pfd);
    }
    pfds->pfd[pfds->fd_count].fd = newfd;
    pfds->pfd[pfds->fd_count].events = POLLIN; // Check ready-to-read

    pfds->fd_count++;
}

void pfds_del(pfds_t *pfds, int idx)
{
    pfds->pfd[idx] = pfds->pfd[pfds->fd_count-1]; // copy the one from the end to it
    pfds->fd_count--;
}

int prom_serve_start(const char *addr, int port);
char prom_sample(time_t curtime, int numsecs, struct devtstat *devtstat, struct sstat *sstat, struct cgchainer *devchain, int ncgroups, int npids, int nexit, unsigned int noverflow, char flag);

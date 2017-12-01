
import numpy as np

TOLERANCE = 1e-3

# seed the numpy RNG
np.random.seed(100)

class Mixed_Gaussians_Model(object):
    def __init__(self, num_classes, num_features):
        self.num_classes = num_classes
        self.num_features = num_features

        # probability of belonging to each class
        self.phi = 1.0/num_classes * np.ones((num_classes,1))

        # mean of each gaussian 
        self.mu = np.random.uniform(0, 100, (num_classes, num_features))

        # covariance of each gaussian
        self.sigma = np.zeros((num_classes, num_features, num_features))
        for j in range(num_classes):
            A = np.random.uniform(0, 100, (num_features, num_features))
            self.sigma[j, :, :] = np.dot(A.T, A)

    def train(self, pkt_files):
        """
        Run through all provided packets and train the parameters
        """
        pkt_data = map(np.load, pkt_files)
        self._train_on_data(pkt_data)

    def _train_on_data(self, pkt_data):
        """Train the model parameters on the given data each set of pkts is treated
           as an epoch with which to update parameters and check convergence
        Inputs:
          - pkts : a numpy matrix (num_pkts, num_features)
        """
        # run the EM algorithm until convergence (i.e. until the params stop changing very much)
        epoch_count = 0
        while True:
            for pkts in pkt_data:
                num_pkts = pkts.shape[0]
                old_phi = np.copy(self.phi)
                old_mu = np.copy(self.mu)
                old_sigma = np.copy(self.sigma)
                posterior = self._E_step(pkts)
                # update the parameters
                self._M_step(posterior, pkts)
                epoch_count += 1
                print 'finished epoch {}'.format(epoch_count)
                if self._has_converged(old_phi, old_mu, old_sigma):
                    print 'Converged after {} epochs'.format(epoch_count)
                    return


    def _E_step(self, pkts):
        """Calculate the posterior for each pkt and class
        Inputs:
           - pkts : shape = (num_pkts, num_features)
        Returns:
           - posterior : shape = (num_classes, num_pkts)
        """
        num_pkts = pkts.shape[0]
        print 'Starting E-Step, num_pkts = {}'.format(num_pkts)
        posterior = np.zeros((self.num_classes, num_pkts))
        for i in range(num_pkts):
            posterior[:,[i]] = self._gaussian_pdf(pkts[[i],:].T)
        return posterior
        print 'Finished E-Step'

    def _M_step(self, posterior, pkts):
        """Update the parameters
        Inputs:
          - posterior : shape = (num_classes, num_pkts)
          - pkts : shape = (num_pkts, num_features)
        """
        print 'Starting M-Step'
        num_pkts = pkts.shape[0]
        wj_sum = np.sum(posterior, axis=1, keepdims=True)
        self.phi = 1.0/num_pkts * wj_sum
        print 'Updated phi = {}'.format(self.phi)
        self.mu = np.dot(posterior, pkts) / wj_sum
        print 'Updated mu = {}'.format(self.mu)
        for j in range(self.num_classes):
            weights = np.diag(posterior[j,:])
            self.sigma[j,:,:] = pkts.T.dot(weights).dot(pkts) / wj_sum[j]
        print 'Updated sigma = {}'.format(self.sigma)

    def _gaussian_pdf(self, x):
        """Evaluate the gaussian pdf at x for each possible class
        Inputs:
          - x : shape = (num_features, 1)
        Returns:
          - likelihood : shape = (num_classes, 1)
        """
        likelihood = np.zeros((self.num_classes, 1))
        n = x.shape[0]
        for j in range(self.num_classes):
            mu = self.mu[[j],:].T
            sigma = self.sigma[j,:,:]
            factor = 1.0/(np.power(2*np.pi, n/2.0) * np.sqrt(np.linalg.det(sigma)))
            # compute exponent in 2 steps
            exp1 = np.dot(-0.5*(x-mu).T, np.linalg.inv(sigma))
            exponent = np.dot(exp1, x-mu)
            # compute probability
            likelihood[j] = factor * np.exp(exponent)
        return likelihood
    

    def _has_converged(self, old_phi, old_mu, old_sigma):
        """Check if the EM alg has converged
        """
        phi_diff = np.linalg.norm(old_phi - self.phi)
        mu_diff = np.linalg.norm(old_mu - self.mu)
        sigma_diff = np.linalg.norm(old_sigma - self.sigma)
        print 'phi_diff = {}, mu_diff = {}, sigma_diff = {}'.format(phi_diff, mu_diff, sigma_diff)
        if (phi_diff < TOLERANCE and mu_diff < TOLERANCE and sigma_diff < TOLERANCE):
            return True
        else:
            return False














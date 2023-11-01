/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright 2013 Yusuke Kawamoto
 */
package bham.leakiest;

import java.util.ArrayList;

/**
 * This class represents a binomial distribution.
 * 
 * @author Yusuke Kawamoto
 * @version 1.2
 */
public class BinomialDist {
	private int noOfSamples;
	private double prob;
	private int[] C = null;
	
	/**
	 * 
	 * @param noOfSamples the number of trials
	 * @param prob success probability in each trial
	 */
	public BinomialDist(int noOfSamples, double prob) {
		if(noOfSamples < 0) {
			System.err.println("Error in BinomialDist.class: The number of samples must be non-negative.");
		}
		this.noOfSamples = noOfSamples;
		
		if(prob < 0 || prob > 1) {
			System.err.println("Error in BinomialDist.class: The probability must be in [0, 1].");
		} else {
			this.prob = prob;
		}
	}


	/**
	 * Returns the number of trials.
	 * 
	 * @return the number of trials
	 */
	public int getNoOfSamples() {
		return this.noOfSamples;
	}


	/**
	 * Returns success probability in each trial.
	 * 
	 * @return success probability in each trial
	 */
	public double getProb() {
		return this.prob;
	}

	
	/**
	 * Calculate the mean of the binomial distribution.
	 * 
	 * @return mean of the binomial distribution
	 */
	public double getMean() {
		return noOfSamples * prob;
	}


	/**
	 * Calculate the variance of the binomial distribution.
	 * 
	 * @return variance of the binomial distribution
	 */
	public double getVariance() {
		return noOfSamples * prob * (1 - prob);
	}


	/**
	 * Calculate the standard deviation of the binomial distribution.
	 * 
	 * @return standard deviation of the binomial distribution
	 */
	public double getStdDev() {
		return Math.sqrt(noOfSamples * prob * (1 - prob));
	}


	/**
	 * Calculate the standard score of the binomial distribution.
	 * 
	 * @param rawScore raw score
	 * @return standard score of the binomial distribution
	 */
	public double getStdScore(double rawScore) {
		//System.out.println(" noOfSample= " + noOfSamples);
		//System.out.println(" rawScore  = " + rawScore);
		//System.out.println(" this.prob = " + this.prob);
		//System.out.println(" getStdDev = " + getStdDev());
		return (double)this.noOfSamples * (rawScore - this.prob) / getStdDev();
	}

	
	/**
	 * Calculates the upper bound for a 95% confidence interval
	 * i.e., the value below which 97.5% of sample take,
	 * by normal approximation.
	 * 
	 * @return the upper bound for a 95% confidence interval
	 */
	public double upperBoundNormal95() {
		return Stats.upperBoundNormal95(this.getMean(), this.getVariance()) / noOfSamples;
	}


	/**
	 * Calculates the upper bound for a 95% confidence interval, lower only
	 * i.e., the value below which 95% of sample take,
	 * by normal approximation.
	 * 
	 * @return the upper bound for a (lower) 95% confidence interval
	 */
	public double upperBoundNormal95Upper() {
		return Stats.upperBoundNormal95Upper(this.getMean(), this.getVariance()) / noOfSamples;
	}


	/**
	 * Calculates the lower bound for a 95% confidence interval
	 * i.e., the value above which 97.5% of sample take,
	 * by normal approximation.
	 * 
	 * @return the lower bound for a 95% confidence interval
	 */
	public double lowerBoundNormal95() {
		return Stats.lowerBoundNormal95(this.getMean(), this.getVariance()) / noOfSamples;
	}


	/**
	 * Calculates the lower bound for a 95% confidence interval, upper only
	 * i.e., the value above which 95% of sample take,
	 * by normal approximation.
	 * 
	 * @return the lower bound for a (upper) 95% confidence interval
	 */
	public double lowerBoundNormal95Lower() { 
		return Stats.lowerBoundNormal95Lower(this.getMean(), this.getVariance()) / noOfSamples;
	}


	/**
	 * Gauss error function (calculated using the Talyor expansion)
	 * <BR>
	 * Note: The returned value has a big error about when z is greater than 4.
	 * 
	 * @param z input to the error function.
	 * @param accuracy a parameter deciding the accuracy of the result.
	 * @return output of the error function.
	 */
	public static double erf(double z, double accuracy) {
		double sum = 0.0;
		double prev = 0.0;
		int n = 0;
		do {
		//for(int n = 0; n < param; n++) {
			double product = 1.0;
			for(int k = 1; k <= n; k++) {
				product *= - z * z / (double)k;
			}
			prev = sum;
			sum += z / (double)(2 * n + 1) * product;
			n++;
			//System.out.println(" sum = " + sum + " prev= " + prev);
		} while(Math.abs(prev - sum) > accuracy);
		//double test = z - Math.pow(z,3)/3.0 + Math.pow(z,5)/10.0 - Math.pow(z,7)/42.0 + Math.pow(z,9)/216.0; 
		//System.out.println(" test= " + test);
		//System.out.println(" sum = " + sum);

		double val = sum * 2.0 / Math.sqrt(Math.PI);
		return val;
	}

	
	public static double erfInv(double v, double accuracy) {
		double sum = 0.0;
		double prev = 0.0;
		int k = 0;
		if(v < -1 - accuracy || v > 1 + accuracy) {
			System.out.println("Error: The first argument of erfInv must be in (-1, 1).");
			System.exit(1);
		}
		
		ArrayList<Double> c = new ArrayList<Double>(); 
		do {
			prev = sum;
			c.add(0.0);
			// Calculate ck
			if(k == 0) {
				c.set(k, 1.0);
			} else {
				double val = 0.0;
				for(int m = 0; m < k; m++) {
					double cm = c.get(m);
					double ck1m = c.get(k-1-m);
					val += cm * ck1m / (double)((m + 1) * (2 * m + 1));
					/*
					if(k > 2940) {
						System.out.println("c[" + m + "]    = " + c.get(m));
						System.out.println("c[" + (k-1-m) + "] = " + c.get(k-1-m));
						System.out.println("deno         = " + (m + 1) * (2 * m + 1));
						System.out.println("val          = " + val);
					}
					*/
					if(Double.isInfinite(val)) {
						//TODO: Give better approximation. 
						//System.out.println("Caution: Reached the limitation of computation and stopped the iteration in erfInv.");
						return prev;
					}
				}
				c.set(k, val);
			}
			sum += c.get(k) / (double)(2 * k + 1) * Math.pow(Math.sqrt(Math.PI) * v / 2.0, 2 * k + 1);
			//System.out.println("c[" + k + "] = " + c.get(k));
			//System.out.println("[" + k + "] sum = " + sum);
			k++;
		} while(Math.abs(prev - sum) > accuracy);
		return sum;
	}

	
	public double WilsonIntervalUpper(double confidenceLevel, double accuracy) {
		double z = erfInv(confidenceLevel, accuracy) * Math.sqrt(2);
		//System.out.println("z: " + z);
		double zzn = z * z / this.noOfSamples;
		double error = z * Math.sqrt((this.prob * (1 - this.prob) / this.noOfSamples) +
									 (z * z / (double)(4 * this.noOfSamples * this.noOfSamples)));
		double numerator = this.prob + zzn / 2.0 + error;
		double denominator = 1.0 + zzn; 
		return numerator / denominator;
	}

	public double WilsonIntervalLower(double confidenceLevel, double accuracy) {
		double z = erfInv(confidenceLevel, accuracy) * Math.sqrt(2);
		//System.out.println("z: " + z);
		double zzn = z * z / this.noOfSamples;
		double error = z * Math.sqrt((this.prob * (1 - this.prob) / this.noOfSamples) +
									 (z * z / (double)(4 * this.noOfSamples * this.noOfSamples)));
		double numerator = this.prob + zzn / 2.0 - error;
		double denominator = 1.0 + zzn; 
		return numerator / denominator;
	}

	

	/**
	 * Calculates the population below a given upper Bound
	 * by using normal approximation.
	 * 
	 * @param upperBound upper bound of the interval
	 * @return the population below upperBound
	 */
	public double populationBelowNormal(double upperBound) {
		double stdScore = getStdScore(upperBound);
		//double accuracy = 0.000000001;
		double accuracy = 0.000000000001;
		double populationRange = 0.5;
		if(Math.abs(stdScore) > 6)
			populationRange = 1;
		else
			populationRange = erf(Math.abs(stdScore) / Math.sqrt(2), accuracy);
		if(stdScore > 0)
			return 0.5 + populationRange/2;
		else 
			return 0.5 - populationRange/2;
	}

	
	/**
	 * Calculates the population below a given upper Bound.
	 * by using Wilson score interval.
	 * 
	 * @param upperBound upper bound of the interval
	 * @return the population below upperBound
	 */
	public double populationBelow(double upperBound) {
		//System.out.println("  upperBound   = " + upperBound);
		double accuracy = 0.000000000001;
		
		//double normalapprox = this.populationBelowNormal(upperBound);
		//System.out.println("  normalapprox = " + normalapprox);
		//double wil = this.WilsonIntervalLower(1 - normalapprox * 2.0, 0.000000000001);
		//System.out.println("  wil          = " + wil);
		
		// Iteration for binary search
		double upperBoundNew = 0.0;
		double prev;
		double searchMin = 0.0;
		double searchMax = 1.0;
		double searchMid;
		//int k = 0;
		do {
			prev = upperBoundNew;
			searchMid = (searchMin + searchMax) / 2;
			upperBoundNew = WilsonIntervalLower(1 - searchMid * 2.0, 0.000000000001);

			//System.out.println("--------[" + k + "]--------");
			//System.out.println("searchMid     = " + searchMid);
			//System.out.println("upperBoundNew = " + upperBoundNew);
			//k++;
			if(upperBoundNew > upperBound) {
				searchMax = searchMid;
			} else {
				searchMin = searchMid;
			}
		} while(Math.abs(upperBoundNew - prev)  > accuracy);
		return searchMid;
	}


	/**
	 * Calculates the population above a given lower Bound.
	 * 
	 * @param lowerBound lower bound of the interval
	 * @return the population above lowerBound
	 */
	public double populationAbove(double lowerBound) {
		double stdScore = getStdScore(lowerBound);
		double accuracy = 0.000000001;
		double populationRange = 0.5;
		if(Math.abs(stdScore) > 6)
			populationRange = 1;
		else
			populationRange = erf(Math.abs(stdScore) / Math.sqrt(2), accuracy);
		if(stdScore > 0)
			return 0.5 - populationRange/2;
		else 
			return 0.5 + populationRange/2;
	}

	
	/**
	 * Returns the probability of getting exactly k successes.
	 * 
	 * @param k the number of successes
	 * @return the probability of getting exactly k successes
	 */
	public double PMF(int k) {
		int kCn = getBinomialCoefficient(k);
		return (double)kCn * Math.pow(prob, k) * Math.pow(1-prob, noOfSamples-k); 
	}


	/**
	 * Returns the binomial coefficient indexed by the number of samples and k.
	 * 
	 * @param k the number of successes
	 * @return the binomial coefficient indexed by the number of samples and k
	 */
	public int getBinomialCoefficient(int k) {
		if(this.noOfSamples < 0) {
			System.err.println("Error: Cannot calculate a binomial coefficient when the number of samples is negative.");
			System.exit(1);
		}
		else if(this.C == null)
			calcBinomialCoefficients(noOfSamples);
		int size = noOfSamples/2 + 1;
		if(k >= size)
			k = noOfSamples - k;
		if(k >= 0 && k <= noOfSamples)
			return this.C[k];
		else
			return -1;
	}


	/*
	 * Calculates the array of binomial coefficients when the number of samples is n.
	 * 
	 * @param n the number of samples
	 */
	private void calcBinomialCoefficients(int n) {
		int size = n/2 + 1;
		//System.out.println("size = " + size);

		C = new int[size];
		C[0] = 1;
		for(int i = 1; i < n; i++) {
			if(i < size)
				C[i] = 1;
			for(int j = Math.min(size-1, i); j > 0; j--) {
				C[j] += C[j-1];
			}
		}
	}


}

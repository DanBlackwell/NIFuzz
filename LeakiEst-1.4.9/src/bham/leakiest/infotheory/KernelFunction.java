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
 * Copyright 2013 Tom Chothia and Yusuke Kawamoto
 */
package bham.leakiest.infotheory;

import java.util.*;
import bham.leakiest.Stats;


/**
 * This file contains the method for estimating a continuous
 * probability distribution from sampled data using a kernel function. 
 *
 * @author Tom Chothia
 * @author Yusuke Kawamoto
 * @version 1.4.9
 */
public class KernelFunction {
	private ArrayList<double[]> DataList;
	private double startPoint;
	private double endPoint;
	private double stepSizeForMI;
	
	private double[] diffRange;
	private double[] h;

	// Constants
	private static final double ERROR = -1;
	
	/**
	 * Parameter to approximate the mutual information for the continuous data
	 */ 
	public static int resolutionForMI = 250;  // by Tom
	//public static int resolutionForMI = 250000; // close to the R program


	/*
	 * Constructs the empty 
	 */
	//public KernelFunction() {}


	/**
	 * Initialises a kernel function with a list of observation data.
	 * 
	 * @param observedDataList list of observation data
	 */
	public KernelFunction(ArrayList<double[]> observedDataList) {
		this.DataList = observedDataList;
		this.diffRange = new double[DataList.size()];
		this.h = new double[DataList.size()];
		
		Iterator<double[]> it = DataList.iterator();
		int i = 0;
		// for each input value
		while(it.hasNext()) {
            double[] Data = it.next();
    		double Max = maxData(Data);
    		double Min = minData(Data);
    		
    		diffRange[i] = Max - Min;
    		h[i] = bandWidth(Data, diffRange[i]);
    		if(i == 0)
    			startPoint = Min-3*h[i];
    		else
    			startPoint = Math.min(startPoint, Min-3*h[i]);
    		endPoint = Math.max(endPoint, Max+3*h[i]);
    		i++;
        }
		stepSizeForMI = (endPoint-startPoint)/(double)resolutionForMI;
		//System.out.println("  stepSizeForMI = " + stepSizeForMI);
	}
	
	/*	
	 * Finds the maximum data
	 */	
	private double maxData(double[] Data) {
		double Max = 0;
		boolean initialize = true;
		for(double value : Data) {
			if(initialize) { // For initial value
				if(!Double.isNaN(value))
					Max = value;
				initialize = false;
			} else {
				if(!Double.isNaN(value))
					Max = Math.max(value, Max);
			}
		}
		return Max;
	}
	
	/*	
	 * Finds the minimum data
	 */	
	private double minData(double[] Data) {
		double Min = 0;
		boolean initialize = true;
		for(double value : Data) {
			if(initialize) { // For initial value
				if(!Double.isNaN(value))
					Min = value;
				initialize = false;
			} else {
				if(!Double.isNaN(value))
					Min = Math.min(value, Min);
			}
		}
		return Min;		
	}

	/*
	 * Calculates the idle bandwidth for data
	 * h = 1.06*min(sd(Y),diff(range(Y))/1.34)*length(Y)^{-1/5}.
	 * 
	 * @param Data
	 * @param diffRange
	 * @return
	 */
	private double bandWidth(double[] Data, double diffRange) {
		double h;
		double sdtDev = Stats.sdtDevSampled(Data);
		if(Double.isNaN(sdtDev))
			h = 1.06*diffRange*(Data.length^(-1/5));
		else
			h = 1.06*Math.min(sdtDev, diffRange*(Data.length^(-1/5)));

		return h;
	}
	
	/*
	 * p(y | x) = 1/Nh \Sigma_i={1,..,N} K((y - Y_i)/h)
	 * @param output
	 * @param Data
	 * @param diffRange
	 * @return
	 */
	private double probEstimate(double output, double[] Data, double diffRange) {
		double h = bandWidth(Data, diffRange);
		
		double sum = 0;
		for(int i = 0; i < Data.length; i++) {
			sum += kernelFunction((output - Data[i]) / h);
		}
		
		if(h <= 0 || Data.length == 0) {
			return ERROR;
		} else {
			return sum / (Data.length * h);
		}
	}
	
	/**
	 * Calculates the empirical input distribution.
	 * @param DataList list of observation data
	 * @return empirical input distribution
	 */
	public double[] probInputDist(ArrayList<double[]> DataList) {
		//Total number of data
		int Total = 0;
		for(double[] dl : DataList) {
			Total += dl.length;
		}
		
		//Estimated input distribution
		double[] dist = new double[DataList.size()];
		for(int i = 0; i < DataList.size(); i++) {
			dist[i] = (double)DataList.get(i).length / (double)Total;
		}
		return dist;
	}
	
	
	/*
	 * Returns the value of kernel function.
	 * See for instance http://en.wikipedia.org/wiki/Kernel_(statistics)
	 * for information on these kernel functions. 
	 */
	private double kernelFunction(double x) {
		return epanechnikov(x);
	}

	/*
	 * Returns the value of kernel function.
	 */
	private double epanechnikov(double x) {
		if(Math.abs(x) <= 1.0) {
			return 3.0 * (1.0 - x * x) / 4.0;
		} else {
			return 0;
		}
	}


	/**
	 * Calculates the estimated mutual information.
	 * This method returns:
	 * <BR>
	 * I(Q,W) = I (X;Y) = &Sigma;_x &int;_y Q(x).W(y|x)log(W(y|x)/Y(y)) dy
	 * = Q(input_0) &int;_y W(y|input_0)log(W(y|input_0)/Y(y)) dy + ... +
	 *   Q(input_k) &int;_y W(y|input_k)log(W(y|input_k)/Y(y)) dy
	 * <BR>
	 * Y(y) = Q(input_0) W(y|input_0) + ... + Q(input_k) W(y|input_k)
	 * <BR>
	 * &int;_y W(y|input_x)log(W(y|input_x)/Y(y)) dy
	 * = &int;_n^{n_1}     W(y|input_x)log(W(y|input_x)/Y(y)) dy
	 * + &int;_{n_1}^{n_2} W(y|input_x)log(W(y|input_x)/Y(y)) dy + ...
	 * <BR> 
	 * where
	 * &int;_{n_1}^{n_2} W(y|input_x)log(W(y|input_x)/Y(y)) dy
	 * ~ W(n_1|input_x)log(W(n_1|input_x)/Y(n_1))*(n_2-n_1)
	 * 
	 * @param inputDist input probability distribution
	 * @param Datalist list of observed data
	 * @return estimated mutual information
	 */
	public double calcContinuousApproxMI(double[] inputDist, ArrayList<double[]> Datalist) {
		double currentPoint = startPoint; // = n_i
		double MIsum = 0;
		double[] probOoutputGivenInput = new double[Datalist.size()]; // = W(y|input_0),W(y|input_1),...,W(y|input_n) 

		// for each interval of observable output
		for(int i = 0; i < resolutionForMI; i++) {
			// calculate probOutput = Y(n_1)
			double probOutput = 0; // initialization
			// for each input value
			for(int x = 0; x < Datalist.size(); x++) {
				probOoutputGivenInput[x] = probEstimate(currentPoint, Datalist.get(x), diffRange[x]);
				if(probOoutputGivenInput[x] != ERROR)
					probOutput += inputDist[x] * probOoutputGivenInput[x];
				else
					return ERROR;
			}
			
			// Int_{n_1}^{n_2} W(y|input)log(W(y|input)/Y(y)) dy
			// ~ W(n_1|input)log(W(n_1|input)/Y(n_1))*(n_2-n_1) = area
			// area =  term*(n_2-n_1)
			// term =  W(n_1|input)log(inner)
			// inner = W(n_1|input)/Y(n_1)
			// 0.log(0/0) = 0
			if(probOutput != 0) {
				for(int x = 0; x < Datalist.size(); x++) {
					double inner = probOoutputGivenInput[x] / probOutput;
					if(probOoutputGivenInput[x] != 0) {
						double term  = probOoutputGivenInput[x] * InfoTheory.log2(inner);
						double area  = term * stepSizeForMI;
						MIsum += inputDist[x] * area;
					}
				}
			}
			currentPoint += stepSizeForMI;
			//System.out.println("MIsum[" + i + "] = " + MIsum + "   probObs = " + probObs);
		}
		return MIsum;
	}

}

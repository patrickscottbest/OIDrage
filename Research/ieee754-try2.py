from math import *
# https://my.numworks.com/python/mrpiay/ieee754
# did not work well, PSB


# main function: call fp(float number n different from 0)
def fp(n):
  # base-2 scientific notation
  global s,e,m
  s,e=0,0
  p=1
  if n<0:s=1
  if fabs(n)>=2:p=-1
  while(p*fabs(n)*pow(2,p*e))<p:
    e=e+1
  if p==-1 and fabs(n)!=2:e=e-1
  m=fabs(n)*pow(2,p*e)
  e=-1*p*e
  np=pow(-1,s)*m*pow(2,e)
  print("\nBase-2 scientific notation:",
      "\nn= (-1)^S x 2^E x M (M=1.F)",
      "\nS="+str(s)+"\tE="+str(e)+"\tM="+str(m),
      "\nn="+str(np))
  print("\nIEEE-754:")
  print("\nHalf precision (binary16):")
  # IEEE-754 half precision (binary16)
  binaryxx(15,5,10)
  print("\nSingle precision (binary32):")
  # IEEE-754 single precision (binary32)
  binaryxx(127,8,23)
  print("\nDouble precision (binary64):")
  # IEEE-754 double precision (binary64)
  binaryxx(1023,11,52)

# IEEE-754 template
def binaryxx(eo,ed,md):
  print("S="+str(s),
      "\nE="+tobin(e+eo,ed)+" ("+str(e+eo)+")",
      "\nF="+tobin(round(modf(m)[0]*pow(2,md)),md)+
      " ("+str(round(modf(m)[0]*pow(2,md)))+")",
      "\nn="+str(pow(-1,s)*(1+round(modf(m)[0]*pow(2,md))/(pow(2,md)))*pow(2,e)))

# integer (n) to binary (b bits)
bits=[]
def tobin(n,b):
  bits.clear()
  np=n
  for c in range(b):
    if pow(2,b-1-c)<=np:
      bits.append(1)
      np=np-pow(2,b-1-c)
    else:
      bits.append(0)
  return "".join(str(i) for i in bits)

# fp(0.048340)
fp(0)
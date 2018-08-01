

def getEdges(G):
	v1 = [] #src node
	v2 = [] #dest node
	w = [] # weigth of src to dst
	for i in G:
		for j in G[i]:
			if G[i][j]!=0:
				w.append(G[i][j])
				v1.append(i)  #can select this to choose special nodes
				v2.append(j)
	return v1,v2,w

def Benllman_Ford(G,v0,inf=9999):
	v1,v2 ,w = getEdges(G)
	#init shortest distance of sources 2 dest
	dis = dict((k,INF) for k in G.keys())
	dis[v0]= 0 
    
    #core 
	for k in range(len(G)-1):
		check = 0
		for i in range (len(w)):
			if dis[v1[i]]+w[i]<dis[v2[i]]:
				dis[v2[i]]=dis[v1[i]]+w[i]
				check=1
		if check == 0:break

	flag = 0
	for i in range(len(w)):
		if dis[v1[i]] + w[i] < dis[v2[i]]:
			flag = 1
			break
 	if flag == 1:
 		return False
 	return dis
if __name__ == "__main__":
	G={1:{1:0, 2:-3 ,5:5},
	2:{2:0, 3:2},
	3:{3:0, 4:3},
	4:{4:0, 5:2},
	5:{5,0}}

	v0 = 1
	dis = Benllman_Ford(G,v0)
	print dis.values()





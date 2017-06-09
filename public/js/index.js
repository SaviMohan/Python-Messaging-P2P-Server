(function() {
  

}).call(this);

function storeScrollPosition(){
	localStorage.setItem("messageBarScrollPosition",document.getElementById('messages').scrollTop);
	
}
setInterval(storeScrollPosition,2000)

var scrollPosition = localStorage.getItem("messageBarScrollPosition");
var divelement = document.getElementById("messages")
divelement.scrollTop = scrollPosition
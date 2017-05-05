/* TODO:
- link buttons
- buttons to switch to fullscreen
- juggle between view and diff modes
- slider/calendar picker
- css
*/
(function(ns){
  ns.last = ns.versions[ns.versions.length - 1];
  ns.previous = ns.versions[ns.versions.length - 2];
  ns.currentwin = "copy";
  ns.currentcopy = "";
  ns.currentorig = "";
  ns.links = {"orig": null, "copy": null};
  ns.text = {"orig": null, "copy": null};
  ns.mergely = {"links": null, "text": null};

  ns.buildUrl = function(version, typ){
    return "monitor/"+ns.name+"/"+version+"."+typ;
  };

  ns.nameVersion = function(version){
    return version.replace(/^(..)(..)(..)-(..)(..)$/, "$3/$2/$1 $4:$5");
  };

  ns.addDiffer = function(typ){
    ns.mergely[typ] = $("#mergely-" + typ)
    ns.mergely[typ].mergely({
      width: 'auto',
      height: 'auto',
      cmsettings: {
        readOnly: true,
        mode: 'text/plain',
        lineNumbers: true,
        lineWrapping: true
      },
      ignorews: true,
      viewport: true,
      bgcolor: "#ddeeff",
    });
    ns.mergely[typ].width($("#mergely-" + typ).width() + 1);
  };

  ns.updateDiffer = function(typ, curwin, version){
    ns[typ][curwin] = ns[typ][version];
    ns.mergely[typ].mergely(
      (curwin === "copy" ? 'l' : 'r') + 'hs',
      ns[typ][version]
    );
    if (ns[typ]["orig"] && ns[typ]["copy"]) {
      ns.mergely[typ].mergely('scrollToDiff', 'next');
    }
  };

  ns.loadVersion = function(version, curwin){
    var url = ns.buildUrl(version, "html"),
      name = ns.nameVersion(version);
    curwin = curwin || ns.currentwin;
    $(".select" + curwin).removeClass('select' + curwin);
    $("#" + version).addClass('select' + curwin);
    $("." + curwin + " a").text(name)
                          .attr("href", url);
    $("." + curwin + " iframe").attr("src", url);
    ["links", "text"].forEach(function(typ){
      ns.mergely[typ].mergely('scrollTo', 'l', 0);
      ns.mergely[typ].mergely('scrollTo', 'r', 0);
      if (ns[typ][version]) {
        ns.updateDiffer(typ, curwin, version);
      } else $.ajax({
        url: ns.buildUrl(version, typ.replace('e', '')),
        dataType: "text",
        success: function(result){
          ns[typ][version] = result;
          ns.updateDiffer(typ, curwin, version);
        }
      });
    });
    ns['current' + curwin] = version;
  };

  ns.loadReal = function(){
    var url = ns.url || "http://regardscitoyens.org";
    $(".selectorig").removeClass('selectorig');
    $("#real").addClass('selectorig');
    $(".orig a").text("live web " + url)
                .attr("href", url);
    $(".orig .content").empty();
    $(".orig iframe").attr("src", url);
    ns.currentorig = "real";
  };

  ns.toggleCurrentWindow = function(){
    ns.currentwin = (ns.currentwin === "orig" ? "copy" : "orig");
  }

  ns.setDimensions = function(){
    var winW = $("#selecter").width(),
      imgW = Math.max(200, Math.min(350, parseInt(winW/ns.versions.length)));
    $("#selecter_large, #screenshots").width((ns.versions.length) * (imgW + 2) + 1);
    $("#versions p, #screenshots img").width(imgW);
    $(".copy iframe, .orig iframe").width((winW - 3) / 2);
    $(".differ").width(winW - 17);
  };

  $(document).ready(function(){
    var versions = $("#versions"),
      screens = $("#screenshots");
    ns.versions.forEach(function(version){
      var textVersion = ns.nameVersion(version),
        p = document.createElement('p'),
        i = document.createElement('img'),
        onclic = function(){
          ns.loadVersion(version);
        };
      p.id = version;
      p.textContent = textVersion;
      i.src = "monitor/" + ns.name + "/" + version + "-small.png";
      i.title = textVersion;
      i.alt = textVersion;
      versions.append(p);
      screens.append(i);
      $(p).click(onclic);
      $(i).click(onclic);
    });
    /*var p = document.createElement('p');
    p.id = "real";
    p.textContent = "live web";
    $(p).click(ns.loadReal);
    versions.append(p);*/
    ns.setDimensions();
    $("#selecter").scrollLeft($("#selecter_large").width());
    ns.addDiffer("links");
    ns.addDiffer("text");
    ns.loadVersion(ns.previous, "copy");
    ns.loadVersion(ns.last, "orig");
    //ns.loadReal();
    $("input[type=radio][name=curwin]").change(ns.toggleCurrentWindow);
    $(window).resize(ns.setDimensions);
  });

})(window.gazouilleur = window.gazouilleur || {});

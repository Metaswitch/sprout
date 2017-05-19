/**
 * @file sproutletplugin.h  Abstract definition for Sproutlet Plug-in interface.
 *
 * Copyright (C) Metaswitch Networks
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef SPROUTLETPLUGIN_H__
#define SPROUTLETPLUGIN_H__

#include "sproutlet.h"

class SproutletPlugin
{
public:
  virtual bool load(struct options& opt, std::list<Sproutlet*>& sproutlets) = 0;
  virtual void unload() = 0;
};

#endif
